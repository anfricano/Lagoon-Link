from __future__ import annotations

import os
import math
import time
import mimetypes
from datetime import datetime
from typing import Optional

import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from werkzeug.routing import BuildError


# ------------------------ App + Config ------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-me"),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///lagoonlink.sqlite"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    WTF_CSRF_ENABLED=True,
    SEND_FILE_MAX_AGE_DEFAULT=0,      # dev: no static caching
    TEMPLATES_AUTO_RELOAD=True,       # dev: live-reload templates
)

# Static font mime types
mimetypes.add_type('font/woff2', '.woff2')
mimetypes.add_type('font/ttf', '.ttf')

# Expose a version for templates (changes each server start)
app.jinja_env.globals['ASSET_VERSION'] = str(int(time.time()))

# Single no-cache hook (dev)
@app.after_request
def add_no_cache_headers(resp):
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# ------------------------ Models ------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    dives = db.relationship("Dive", backref="user", passive_deletes=True)

    def set_password(self, pw: str) -> None:
        # Force PBKDF2 to avoid hashlib.scrypt on systems that lack it
        self.password_hash = generate_password_hash(pw, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Dive(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lon = db.Column(db.Float, nullable=False)
    depth_ft = db.Column(db.Integer)
    duration_min = db.Column(db.Integer)
    vis_ft = db.Column(db.Integer)
    water_temp_f = db.Column(db.Integer, nullable=True)
    notes = db.Column(db.Text)
    is_public = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ------------------------ Template Globals ------------------------
@app.context_processor
def inject_globals():
    return {
        "Globals": {
            "APP_NAME": "lagoonlink",
            "logo_url": url_for("static", filename="logo.svg"),
            "favicon_url": url_for("static", filename="favicon.svg"),
        }
    }


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    try:
        return db.session.get(User, int(user_id))  # SQLAlchemy 2.0 style
    except Exception:
        return None


# ------------------------ CLI ------------------------
@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
    print("DB initialized.")


# ------------------------ Nearby / Marine Helpers ------------------------
_marine_cache = {}  # key: (round(lat,2), round(lon,2)) -> {"ts": epoch, "data": {...}}
_MARINE_TTL = 15 * 60  # 15 minutes


def _haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dlmb/2)**2
    return 2 * R * math.asin(math.sqrt(a))


def _fetch_marine(lat, lon):
    key = (round(lat, 2), round(lon, 2))
    now = time.time()
    if key in _marine_cache and (now - _marine_cache[key]["ts"]) < _MARINE_TTL:
        return _marine_cache[key]["data"]

    url = "https://marine-api.open-meteo.com/v1/marine"
    params = {
        "latitude": lat,
        "longitude": lon,
        "hourly": ",".join([
            "wind_speed_10m", "wind_direction_10m",
            "wave_height", "wave_direction", "wave_period",
            "sea_surface_temperature"
        ]),
        "timezone": "auto",
    }
    try:
        r = requests.get(url, params=params, timeout=8)
        r.raise_for_status()
        j = r.json()
        h = j.get("hourly", {})

        def last(name):
            arr = h.get(name) or []
            return arr[-1] if arr else None

        data = {
            "wind_speed_kt": round((last("wind_speed_10m") or 0) * 0.539957, 1),  # m/s -> kt
            "wind_dir": last("wind_direction_10m"),
            "wave_height_m": last("wave_height"),
            "wave_dir": last("wave_direction"),
            "wave_period_s": last("wave_period"),
            "sst_c": last("sea_surface_temperature"),
        }
        _marine_cache[key] = {"ts": now, "data": data}
        return data
    except Exception:
        return None


# ------------------------ Routes ------------------------
@app.route("/")
def index():
    try:
        community_url = url_for("community_map")
    except BuildError:
        community_url = url_for("community")
    return render_template("index.html", community_url=community_url)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(pw):
            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        display = (request.form.get("display_name") or "").strip()
        if not email or not pw:
            flash("Email and password are required.", "warning")
            return render_template("signup.html")
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return render_template("signup.html")
        u = User(email=email, display_name=display or email.split("@")[0])
        u.set_password(pw)
        db.session.add(u)
        db.session.commit()
        login_user(u)
        flash("Account created.", "success")
        return redirect(url_for("dashboard"))
    return render_template("signup.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    dives = Dive.query.filter_by(user_id=current_user.id).order_by(Dive.created_at.desc()).all()
    return render_template("dashboard.html", dives=dives)


@app.route("/dives/new", methods=["GET", "POST"])
@login_required
def dives_new():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        lat = request.form.get("lat")
        lon = request.form.get("lon")
        depth_ft = request.form.get("depth_ft")
        duration_min = request.form.get("duration_min")
        vis_ft = request.form.get("vis_ft")
        water_temp_f = request.form.get("water_temp_f")
        notes = (request.form.get("notes") or "").strip()
        is_public = request.form.get("is_public") == "on"
        try:
            lat = float(lat)
            lon = float(lon)
        except Exception:
            flash("Latitude/Longitude must be numbers.", "warning")
            return render_template("new_dive.html")
        d = Dive(
            user_id=current_user.id, name=name or "Dive", lat=lat, lon=lon,
            depth_ft=int(depth_ft) if depth_ft else None,
            duration_min=int(duration_min) if duration_min else None,
            vis_ft=int(vis_ft) if vis_ft else None,
            water_temp_f=int(water_temp_f) if water_temp_f else None,
            notes=notes, is_public=is_public
        )
        db.session.add(d)
        db.session.commit()
        flash("Dive saved.", "success")
        return redirect(url_for("dashboard"))
    return render_template("new_dive.html")


@app.route("/dives/<int:dive_id>/toggle_public", methods=["POST"])
@login_required
def toggle_public(dive_id: int):
    d = Dive.query.filter_by(id=dive_id, user_id=current_user.id).first_or_404()
    d.is_public = not d.is_public
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/map")
@login_required
def map_page():
    return render_template("map.html")


@app.route("/api/my_dives")
@login_required
def api_my_dives():
    dives = Dive.query.filter_by(user_id=current_user.id).order_by(Dive.created_at.desc()).all()
    return jsonify([{
        "id": d.id, "name": d.name, "lat": d.lat, "lon": d.lon,
        "notes": d.notes or "", "is_public": d.is_public,
        "water_temp_f": d.water_temp_f,
        "created_at": d.created_at.isoformat()
    } for d in dives])


@app.route("/community")
def community():
    q = Dive.query.filter_by(is_public=True).order_by(Dive.created_at.desc())
    if request.args.get("format") == "json":
        return jsonify([{"id": d.id, "name": d.name, "lat": d.lat, "lon": d.lon} for d in q.limit(1000)])
    dives = q.limit(200).all()
    return render_template("community.html", dives=dives)


@app.route("/api/public_dives")
def api_public_dives():
    dives = (
        Dive.query.filter_by(is_public=True)
        .order_by(Dive.created_at.desc())
        .limit(2000)
        .all()
    )
    return jsonify([
        {"id": d.id, "name": d.name, "lat": d.lat, "lon": d.lon, "notes": d.notes or ""}
        for d in dives
    ])


@app.route("/community/map")
def community_map():
    return render_template("community_map.html")


@app.route("/api/nearby_spots")
def api_nearby_spots():
    """Return nearby public (and your own) dives with live marine stats."""
    try:
        lat = float(request.args.get("lat", ""))
        lon = float(request.args.get("lon", ""))
    except Exception:
        return jsonify({"error": "lat/lon required"}), 400

    radius_km = float(request.args.get("radius_km", 100))
    q_public = Dive.query.filter_by(is_public=True)
    spots = list(q_public)
    if current_user.is_authenticated:
        mine = Dive.query.filter_by(user_id=current_user.id).all()
        spots_ids = {s.id for s in spots}
        spots.extend(m for m in mine if m.id not in spots_ids)

    seen, rows = set(), []
    for d in spots:
        if d.id in seen:
            continue
        seen.add(d.id)
        dist = _haversine_km(lat, lon, d.lat, d.lon)
        if dist <= radius_km:
            live = _fetch_marine(d.lat, d.lon)
            rows.append({
                "id": d.id,
                "name": d.name,
                "lat": d.lat, "lon": d.lon,
                "distance_km": round(dist, 1),
                "notes": d.notes or "",
                "is_public": d.is_public,
                "live": live,
            })

    rows.sort(key=lambda r: r["distance_km"])
    return jsonify(rows[:8])


# ------------------------ Tides API (resilient) ------------------------
NOAA_META_BASE = "https://api.tidesandcurrents.noaa.gov/mdapi/prod/webapi/stations.json"
NOAA_DATA_BASE = "https://api.tidesandcurrents.noaa.gov/api/prod/datagetter"
NOAA_STATION_DETAIL = "https://api.tidesandcurrents.noaa.gov/mdapi/prod/webapi/stations/{id}.json"

_TIDES_CACHE = {}  # key: station_id -> {"ts": epoch, "meta": {...}, "series": [...], "hilo": [...], "stale": bool}
_TIDES_TTL = 10 * 60  # 10 minutes


def _tide_haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0088
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = phi2 - phi1
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return R * (2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)))


def _nearest_tide_station(lat, lon, max_km=250.0):
    """Closest NOAA tide station within max_km; else regional/default."""
    try:
        lat = float(lat); lon = float(lon)
    except Exception:
        return {"id": "8452660", "name": "Newport, RI", "state": "RI",
                "lat": 41.504, "lon": -71.326, "distance_km": None}

    for delta in (0.5, 1.0, 2.5):
        bbox = f"{lon - delta},{lat - delta},{lon + delta},{lat + delta}"
        try:
            r = requests.get(NOAA_META_BASE, params={"type": "tidepredictions", "bbox": bbox}, timeout=12)
            r.raise_for_status()
            stations = r.json().get("stations", []) or []
        except Exception:
            stations = []
        if not stations:
            continue

        best, best_d = None, 1e12
        for s in stations:
            try:
                s_lat = float(s["lat"]); s_lon = float(s["lng"])
                d = _tide_haversine_km(lat, lon, s_lat, s_lon)
            except Exception:
                continue
            if s.get("status", "").lower() == "active" and d < best_d:
                best, best_d = s, d
        if best is None:
            for s in stations:
                try:
                    s_lat = float(s["lat"]); s_lon = float(s["lng"])
                    d = _tide_haversine_km(lat, lon, s_lat, s_lon)
                except Exception:
                    continue
                if d < best_d:
                    best, best_d = s, d

        if not best or best_d > max_km:
            continue
        try:
            if abs(float(best["lat"]) - lat) > 10 and abs(float(best["lng"]) - lon) > 10:
                continue
        except Exception:
            pass

        return {
            "id": str(best["id"]),
            "name": best.get("name", "NOAA Station"),
            "state": best.get("state", ""),
            "lat": float(best.get("lat")) if best.get("lat") is not None else None,
            "lon": float(best.get("lng")) if best.get("lng") is not None else None,
            "distance_km": round(best_d, 2),
        }

    # Regional defaults (continental US bands)
    if -90 <= lon <= -60 and 25 <= lat <= 50:   # East Coast / NE
        return {"id": "8452660", "name": "Newport, RI", "state": "RI",
                "lat": 41.504, "lon": -71.326, "distance_km": None}
    if -105 <= lon < -90 and 25 <= lat <= 35:   # Gulf
        return {"id": "8771450", "name": "Galveston Pier 21, TX", "state": "TX",
                "lat": 29.31, "lon": -94.79, "distance_km": None}
    if -125 <= lon < -105 and 30 <= lat <= 50:  # West Coast
        return {"id": "9414290", "name": "San Francisco, CA", "state": "CA",
                "lat": 37.806, "lon": -122.465, "distance_km": None}

    # Final default
    return {"id": "8452660", "name": "Newport, RI", "state": "RI",
            "lat": 41.504, "lon": -71.326, "distance_km": None}


def _fetch_hourly_predictions(station_id, hours=36, datum="MLLW", units="english"):
    params = {
        "product": "predictions",
        "application": "LagoonLink",
        "station": station_id,
        "datum": datum,
        "time_zone": "gmt",
        "units": units,
        "interval": "h",
        "range": str(hours + 6),  # include a little history
        "format": "json",
    }
    r = requests.get(NOAA_DATA_BASE, params=params, timeout=12)
    r.raise_for_status()
    out = []
    for p in r.json().get("predictions", []):
        try:
            out.append({"t": p["t"], "v": float(p["v"])})
        except Exception:
            pass
    return out


def _fetch_highs_lows(station_id, datum="MLLW", units="english"):
    params = {
        "product": "predictions",
        "application": "LagoonLink",
        "station": station_id,
        "datum": datum,
        "time_zone": "gmt",
        "units": units,
        "interval": "hilo",
        "range": "48",
        "format": "json",
    }
    r = requests.get(NOAA_DATA_BASE, params=params, timeout=12)
    r.raise_for_status()
    out = []
    for it in r.json().get("predictions", []):
        try:
            out.append({"t": it["t"], "v": float(it["v"]), "type": it["type"]})
        except Exception:
            pass
    return out


def _fetch_predictions_resilient(station_id: str):
    """Try smaller ranges + retries; raise if all fail."""
    for hrs in (36, 30, 24):
        for _ in range(2):  # two tries per size
            try:
                return _fetch_hourly_predictions(station_id, hours=hrs)
            except requests.HTTPError as e:
                code = getattr(e.response, "status_code", None)
                if code in (502, 503, 504):
                    continue
                raise
            except requests.RequestException:
                continue
    raise RuntimeError("NOAA predictions unavailable")


def _fetch_hilo_resilient(station_id: str):
    for _ in range(2):
        try:
            return _fetch_highs_lows(station_id)
        except requests.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code in (502, 503, 504):
                continue
            raise
        except requests.RequestException:
            continue
    # If hilo fails, just return empty; chart still renders
    return []


def _station_meta_by_id(station_id: str):
    """Reliable metadata lookup for a single station id (avoids mislabels)."""
    try:
        url = NOAA_STATION_DETAIL.format(id=station_id)
        r = requests.get(url, params={"type": "tidepredictions"}, timeout=12)
        r.raise_for_status()
        j = r.json()
        st = j.get("stations", {})
        if isinstance(st, list):
            st = st[0] if st else {}
        return {
            "id": station_id,
            "name": st.get("name") or f"NOAA Station {station_id}",
            "state": st.get("state", ""),
            "lat": float(st["lat"]) if st.get("lat") else None,
            "lon": float(st["lng"]) if st.get("lng") else None,
        }
    except Exception:
        return {"id": station_id, "name": f"NOAA Station {station_id}", "state": "", "lat": None, "lon": None}


@app.route("/api/tides", methods=["GET"])
def api_tides():
    station = request.args.get("station")
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    max_km = request.args.get("max_km", default=250.0, type=float)

    # Choose station and meta
    if not station:
        meta = (_nearest_tide_station(lat, lon, max_km=max_km)
                if (lat is not None and lon is not None)
                else {"id": "8452660", "name": "Newport, RI", "state": "RI",
                      "lat": 41.504, "lon": -71.326})
        station = meta["id"]
    else:
        meta = _station_meta_by_id(station)

    now = time.time()
    cached = _TIDES_CACHE.get(station)
    if cached and now - cached["ts"] < _TIDES_TTL:
        out = dict(cached)
        out["meta"] = meta  # ensure label is up-to-date
        return jsonify({"station": {**meta, "point_count": len(out["series"]), "stale": out.get("stale", False)},
                        "series": out["series"], "hilo": out["hilo"]})

    # Fetch live with resilience; fall back to stale cache if live fails
    try:
        series = _fetch_predictions_resilient(station)
        hilo = _fetch_hilo_resilient(station)
        payload = {"ts": now, "meta": meta, "series": series, "hilo": hilo, "stale": False}
        _TIDES_CACHE[station] = payload
        meta_out = {**meta, "point_count": len(series), "stale": False}
        return jsonify({"station": meta_out, "series": series, "hilo": hilo})
    except Exception:
        if cached:
            # Serve stale cache so the chart still renders
            meta_out = {**meta, "point_count": len(cached["series"]), "stale": True}
            return jsonify({"station": meta_out, "series": cached["series"], "hilo": cached["hilo"]})
        return jsonify({"error": "Tide data temporarily unavailable from NOAA."}), 502
# ---------------------- END Tides API ----------------------


# ------------------------ Debug Routes ------------------------
@app.get("/__routes")
def __routes():
    return {"routes": [str(r) for r in app.url_map.iter_rules()]}


# ------------------------ Main ------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
