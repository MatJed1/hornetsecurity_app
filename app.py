from flask import Flask, render_template, request, jsonify, Response, send_from_directory
import requests
import json
import csv
import io
import zipfile
import time
import random
import os
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

# Directory to drop finished ZIPs for download
EXPORT_DIR = os.path.join(os.getcwd(), "exports")
os.makedirs(EXPORT_DIR, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

# ---------------------- Helpers ----------------------
def safe_post(url, headers, payload, max_retries=6, base_sleep=1.0, timeout=120):
    """POST with exponential backoff + jitter. Honors Retry-After for 429."""
    attempt = 0
    while True:
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        except requests.exceptions.RequestException as e:
            if attempt >= max_retries:
                return None, f"Network error after {attempt} retries: {str(e)}"
            sleep_s = base_sleep * (2 ** attempt) + random.uniform(0, 0.6)
            time.sleep(sleep_s); attempt += 1; continue

        if 200 <= r.status_code < 300:
            return r, None

        if r.status_code == 429:
            if attempt >= max_retries:
                return r, f"429 rate limited (exceeded retries). Body: {r.text[:300]}"
            retry_after = r.headers.get("Retry-After")
            if retry_after:
                try:
                    sleep_s = float(retry_after)
                except ValueError:
                    sleep_s = base_sleep * (2 ** attempt)
            else:
                sleep_s = base_sleep * (2 ** attempt) + random.uniform(0, 0.6)
            time.sleep(sleep_s); attempt += 1; continue

        if 500 <= r.status_code < 600:
            if attempt >= max_retries:
                return r, f"{r.status_code} server error (exceeded retries). Body: {r.text[:300]}"
            sleep_s = base_sleep * (2 ** attempt) + random.uniform(0, 0.6)
            time.sleep(sleep_s); attempt += 1; continue

        return r, f"{r.status_code} {r.reason}. Body: {r.text[:300]}"

def parse_iso_z(dt_str: str) -> datetime:
    if dt_str.endswith('Z'):
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    try:
        return datetime.fromisoformat(dt_str)
    except Exception:
        return datetime.fromisoformat(dt_str.split('T')[0]).replace(tzinfo=timezone.utc)

def fmt_iso_local(dt: datetime) -> str:
    tz = timezone(timedelta(hours=8))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local_dt = dt.astimezone(tz).replace(microsecond=0)
    return local_dt.isoformat()   # e.g. 2025-09-09T21:30:00+08:00

# ---------------------- Object ID ----------------------
@app.route('/get_object_id', methods=['POST'])
def get_object_id():
    api_token = request.form.get('api_token')
    user_name = request.form.get('user_name')
    if not api_token or not user_name:
        return jsonify({'error': 'API token and user name are required'}), 400
    url = f'https://cp.hornetsecurity.com/api/v0/object/?name={user_name}'
    headers = {'Authorization': f'Token {api_token}'}
    try:
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        if data and 'object_id' in data:
            return jsonify({
                'object_id': data['object_id'],
                'user_email': data.get('name', user_name),
                'success': f'Object ID found for user: {user_name}',
                'details': {
                    'name': data.get('name'),
                    'type': data.get('type'),
                    'parent': data.get('parent'),
                    'path': data.get('path')
                }
            })
        else:
            return jsonify({'error': 'Object ID not found for the given user'}), 404
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'API request failed: {str(e)}'}), 500

# ---------------------- Single CSV (kept) ----------------------
@app.route('/export_emails', methods=['POST'])
def export_emails():
    api_token = request.form.get('api_token')
    object_id = request.form.get('object_id')
    user_email = request.form.get('user_email', '')
    user_email_filter = request.form.get('user_email_filter', '')
    date_from = request.form.get('date_from')
    date_to = request.form.get('date_to')

    if not all([api_token, object_id, date_from, date_to]):
        return jsonify({'error': 'API token, Object ID, and date range are required'}), 400

    url = f'https://cp.hornetsecurity.com/api/v0/emails/_export/?object_id={object_id}'
    headers = {'Authorization': f'Token {api_token}', 'Content-Type': 'application/json'}

    payload = {
        "offset": 0,
        "limit": 10000,
        "date_from": date_from,
        "date_to": date_to,
        "export_type": "download",
        "export_keys": [
            "date","crypt_type_in","crypt_type_out","owner","comm_partner","direction",
            "source_hostname","destination_hostname","gateway","source_ip","destination_ip",
            "subject","reason","reason_intern","status","size","msg_id","message_id",
            "classification","smtp_status_code","smtp_status","last_remediation_actions"
        ]
    }
    if user_email_filter: payload["email"] = user_email_filter
    elif user_email: payload["email"] = user_email

    resp, err = safe_post(url, headers, payload, max_retries=4, base_sleep=0.8)
    if err: return jsonify({'error': f'Export failed: {err}'}), 502

    ctype = resp.headers.get('content-type','')
    cdisp = resp.headers.get('content-disposition','')
    if 'text/csv' in ctype or 'application/octet-stream' in ctype or 'attachment' in cdisp:
        clean = (user_email or user_email_filter or 'all').replace('@','_at_').replace('.','_')
        fn = f'email_export_{clean}_{date_from.split("T")[0]}_{date_to.split("T")[0]}.csv'
        def generate():
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk: yield chunk
        return Response(generate(), mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename={fn}',
                                 'Content-Type': 'text/csv'})
    try:
        return jsonify({'error': f'API returned non-CSV response: {resp.json()}'}), 500
    except:
        return jsonify({'error': f'API returned unexpected response type: {ctype}'}), 500

# ---------------------- Daily export with LIVE PROGRESS (SSE) ----------------------
@app.route('/export_emails_daily_sse', methods=['POST'])
def export_emails_daily_sse():
    """
    Streams progress logs while writing one CSV per calendar day (and sub-slicing
    days that exceed 10k rows). Fixes: avoid zero-length slices and duplicate
    ERROR files in ZIP; also eliminates end-of-day +1s WARN.
    """
    import uuid

    api_token = request.form.get('api_token')
    object_id = request.form.get('object_id')
    user_email = request.form.get('user_email', '')
    user_email_filter = request.form.get('user_email_filter', '')
    date_from = request.form.get('date_from')
    date_to = request.form.get('date_to')

    # knobs
    try:
        batch_size = min(int(request.form.get('batch_size', '10000')), 10000)
    except ValueError:
        batch_size = 10000
    try:
        throttle_ms = max(0, int(request.form.get('throttle_ms', '800')))
    except ValueError:
        throttle_ms = 800
    try:
        max_retries = max(0, int(request.form.get('max_retries', '6')))
    except ValueError:
        max_retries = 6

    if not all([api_token, object_id, date_from, date_to]):
        return jsonify({'error': 'API token, Object ID, and date range are required'}), 400

    url = f'https://cp.hornetsecurity.com/api/v0/emails/_export/?object_id={object_id}'
    headers = {'Authorization': f'Token {api_token}', 'Content-Type': 'application/json'}

    clean_user = (user_email_filter or user_email or 'all').replace('@','_at_').replace('.','_')
    from_clean = date_from.split('T')[0]
    to_clean = date_to.split('T')[0]
    job_id = f"{clean_user}_{from_clean}_{to_clean}_{int(time.time())}"
    zip_name = f'email_exports_daily_{job_id}.zip'
    zip_path = os.path.join(EXPORT_DIR, zip_name)

    base_payload = {
        "offset": 0,
        "limit": batch_size,
        "date_from": date_from,
        "date_to": date_to,
        "export_type": "download",
        "export_keys": [
            "date","crypt_type_in","crypt_type_out","owner","comm_partner","direction",
            "source_hostname","destination_hostname","gateway","source_ip","destination_ip",
            "subject","reason","reason_intern","status","size","msg_id","message_id",
            "classification","smtp_status_code","smtp_status","last_remediation_actions"
        ]
    }
    if user_email_filter: base_payload["email"] = user_email_filter
    elif user_email: base_payload["email"] = user_email

    def fetch_slice(ws: datetime, we: datetime):
        # guard: never call API with empty/negative window
        if we <= ws:
            raise ValueError(f"Zero-length window {fmt_iso_z(ws)} → {fmt_iso_z(we)}")
        payload = dict(base_payload)
        payload["date_from"] = fmt_iso_z(ws)
        payload["date_to"]   = fmt_iso_z(we)
        resp, err = safe_post(url, headers, payload, max_retries=max_retries, base_sleep=1.0)
        if err:
            raise requests.exceptions.HTTPError(err, response=resp)
        ctype = resp.headers.get('content-type','')
        if ('text/csv' not in ctype and
            'octet-stream' not in ctype and
            'attachment' not in resp.headers.get('content-disposition','')):
            raise requests.exceptions.HTTPError(f'Unexpected content-type {ctype}', response=resp)
        txt = resp.text
        lines = txt.splitlines()
        return lines, txt

    def event_stream():
        # SSE helpers
        def send(event, **data):
            yield f"event: {event}\n"
            yield f"data: {json.dumps(data)}\n\n"

        start = parse_iso_z(date_from)
        end   = parse_iso_z(date_to)
        if start >= end:
            yield from send("error", message="date_from must be earlier than date_to")
            yield from send("done", zip=None);  return

        yield from send("start", job_id=job_id, range=[fmt_iso_z(start), fmt_iso_z(end)],
                        batch_size=batch_size, throttle_ms=throttle_ms)

        total_rows = 0
        total_parts = 0

        with zipfile.ZipFile(zip_path, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
            cur_day = start.replace(hour=0, minute=0, second=0, microsecond=0)
            last_day = end.replace(hour=0, minute=0, second=0, microsecond=0)

            while cur_day <= last_day:
                # Day window is inclusive on both ends in Hornet; we’ll work inclusive and
                # advance carefully to avoid overlap and zero-length tails.
                day_start = max(cur_day, start)
                day_end   = min(cur_day + timedelta(days=1) - timedelta(seconds=1), end)

                # If this day is entirely outside range, skip
                if day_end < day_start:
                    cur_day += timedelta(days=1)
                    continue

                slice_start = day_start
                slice_index = 0
                min_slice = timedelta(minutes=30)
                # begin with full remaining for the day
                slice_dur = (day_end - day_start) + timedelta(seconds=0)

                while slice_start <= day_end:
                    # remaining window within the day
                    remaining = (day_end - slice_start) + timedelta(seconds=1)  # allow a final 1s window

                    if remaining <= timedelta(seconds=0):
                        break

                    cur_dur = min(slice_dur, remaining)
                    if cur_dur < min_slice:
                        cur_dur = min_slice
                    ws = slice_start
                    we = min(slice_start + cur_dur, day_end)

                    # If rounding made we == ws, push we by 1s (but clamp to day_end)
                    if we <= ws:
                        we = ws + timedelta(seconds=1)
                        if we > day_end:
                            # Nothing to process left in this day
                            yield from send("warn", day=cur_day.strftime("%Y-%m-%d"),
                                            slice=[fmt_iso_z(ws), fmt_iso_z(we)],
                                            message="skipped zero-length slice")
                            break

                    while True:
                        try:
                            lines, csv_text = fetch_slice(ws, we)
                        except ValueError as ve:
                            # Our guard tripped (zero-length) – unique error name & continue
                            err_name = f'ERROR_{ws.strftime("%Y%m%dT%H%M%SZ")}_{we.strftime("%Y%m%dT%H%M%SZ")}_{uuid.uuid4().hex[:6]}.txt'
                            zf.writestr(err_name, str(ve))
                            yield from send("warn", day=cur_day.strftime("%Y-%m-%d"),
                                            slice=[fmt_iso_z(ws), fmt_iso_z(we)],
                                            message="skipped zero-length window")
                            break
                        except requests.exceptions.HTTPError as e:
                            # Record error with UNIQUE filename to avoid duplicate ZIP entries
                            err_name = f'ERROR_{ws.strftime("%Y%m%dT%H%M%SZ")}_{we.strftime("%Y%m%dT%H%M%SZ")}_{uuid.uuid4().hex[:6]}.txt'
                            detail = getattr(e, 'response', None)
                            detail_txt = (detail.text[:400] if detail is not None else str(e))
                            zf.writestr(err_name, f'API refused slice {fmt_iso_z(ws)} to {fmt_iso_z(we)}:\n{detail_txt}')
                            yield from send("warn", day=cur_day.strftime("%Y-%m-%d"),
                                            slice=[fmt_iso_z(ws), fmt_iso_z(we)],
                                            message="API refused slice; recorded error and continued")
                            break

                        data_rows = max(0, len(lines) - 1) if lines else 0
                        if data_rows >= batch_size and (we - ws) > min_slice:
                            # Too many rows → shrink time window and retry this same start
                            new_we = ws + (we - ws) / 2
                            if (new_we - ws) < min_slice:
                                new_we = ws + min_slice
                            if new_we <= ws:
                                new_we = ws + timedelta(seconds=1)
                            we = min(new_we, day_end)
                            continue

                        if data_rows > 0:
                            slice_index += 1
                            total_rows += data_rows
                            total_parts += 1
                            suffix = '' if slice_index == 1 else f'_{slice_index:02d}'
                            fname = f'email_{clean_user}_{cur_day.strftime("%Y%m%d")}{suffix}.csv'
                            zf.writestr(fname, csv_text)
                            yield from send("part",
                                            day=cur_day.strftime("%Y-%m-%d"),
                                            part=slice_index,
                                            rows=data_rows,
                                            slice=[fmt_iso_z(ws), fmt_iso_z(we)],
                                            file=fname)
                        else:
                            yield from send("part",
                                            day=cur_day.strftime("%Y-%m-%d"),
                                            part=slice_index,
                                            rows=0,
                                            slice=[fmt_iso_z(ws), fmt_iso_z(we)],
                                            file=None)

                        break  # processed this sub-slice

                    time.sleep(throttle_ms / 1000.0)

                    # ---- ADVANCE (fix): only +1s if there is still time left in this day ----
                    if we < day_end:
                        slice_start = we + timedelta(seconds=1)  # more to do within the day
                    else:
                        # exactly at the day's end — stop the day loop cleanly (no micro slice)
                        break

                cur_day += timedelta(days=1)

            manifest = f"""Export summary (daily split with progress)
User/email filter: {user_email_filter or user_email or 'all'}
Range: {date_from} → {date_to}
Batch size (per CSV): {batch_size}
Throttle between requests: {throttle_ms} ms
Max retries (per request): {max_retries}
Total rows (approx): {total_rows}
CSV files (parts): {total_parts}
"""
            zf.writestr('MANIFEST.txt', manifest)

        yield from send("done", zip=f"/download/{os.path.basename(zip_path)}",
                        parts=total_parts, rows=total_rows)

    return Response(event_stream(), mimetype='text/event-stream')

# ---------------------- Download ----------------------
@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(EXPORT_DIR, filename, as_attachment=True)

# ---------------------- Debug preview (kept) ----------------------
@app.route('/export_emails_info', methods=['POST'])
def export_emails_info():
    api_token = request.form.get('api_token')
    object_id = request.form.get('object_id')
    user_email = request.form.get('user_email', '')
    user_email_filter = request.form.get('user_email_filter', '')
    date_from = request.form.get('date_from')
    date_to = request.form.get('date_to')

    if not all([api_token, object_id, date_from, date_to]):
        return jsonify({'error': 'All fields are required'}), 400

    url = f'https://cp.hornetsecurity.com/api/v0/emails/_export/?object_id={object_id}'
    headers = {'Authorization': f'Token {api_token}', 'Content-Type': 'application/json'}
    payload = {
        "offset": 0,
        "limit": 50,
        "date_from": date_from,
        "date_to": date_to,
        "export_type": "download",
        "export_keys": ["date","owner","comm_partner","direction","subject","status","size","classification"]
    }
    if user_email_filter: payload["email"] = user_email_filter
    elif user_email: payload["email"] = user_email

    resp, err = safe_post(url, headers, payload, max_retries=3, base_sleep=0.8)
    if err: return jsonify({'error': f'Export (debug) failed: {err}'}), 502

    ctype = resp.headers.get('content-type','')
    if 'text/csv' in ctype:
        csv_data = resp.text
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        rows = list(csv_reader)
        return jsonify({'success': f'CSV export ready ({len(rows)} rows)',
                        'preview': rows[:5],
                        'total_rows': len(rows),
                        'headers': list(csv_reader.fieldnames) if csv_reader.fieldnames else []})
    else:
        return jsonify({'response': resp.text[:1000], 'content_type': ctype, 'status_code': resp.status_code})

if __name__ == '__main__':
    app.run(debug=True)
