"""Film the real SOC console at 30 fps: login as CISO → incidents → blast map → approve with rationale → sign out → analyst (view-only)."""
import base64, subprocess, os, time, json
from pathlib import Path
from playwright.sync_api import sync_playwright
here = Path(__file__).parent; FPS = 30
out_login, out_console = here/"ui"/"login.mp4", here/"ui"/"console.mp4"
CURSOR = """(()=>{if(window.__cur)return;const c=document.createElement('div');c.id='__cur';c.style.cssText='position:fixed;z-index:999999;width:22px;height:22px;pointer-events:none;left:0;top:0;transform:translate(-3px,-2px)';
c.innerHTML='<svg width="22" height="22" viewBox="0 0 24 24"><path d="M4 2 L20 12 L12 13.5 L16 21 L13 22 L9.5 14.5 L4 19 Z" fill="#fff" stroke="#000" stroke-width="1.4"/></svg>';document.body.appendChild(c);window.__cur=c;window.__pos=[960,540]})()"""
class Film:
    def __init__(self, pg, path):
        self.pg, self.path = pg, path; self.cdp = pg.context.new_cdp_session(pg); self.n = 0
        self.ff = subprocess.Popen(["ffmpeg","-y","-loglevel","error","-f","image2pipe","-vcodec","mjpeg","-framerate",str(FPS),"-i","-","-c:v","libx264","-preset","medium","-crf","19","-pix_fmt","yuv420p",str(path)], stdin=subprocess.PIPE)
        self.pos = (960, 540)
    def frame(self):
        r = self.cdp.send("Page.captureScreenshot", {"format":"jpeg","quality":92}); self.ff.stdin.write(base64.b64decode(r["data"])); self.n += 1
    def hold(self, s):
        for _ in range(int(s*FPS)): self.frame()
    def move(self, x, y, s=0.6):
        x0, y0 = self.pos; n = max(1, int(s*FPS))
        for i in range(1, n+1):
            k = i/n; k = k*k*(3-2*k); cx, cy = x0+(x-x0)*k, y0+(y-y0)*k
            self.pg.evaluate("([x,y])=>{window.__cur.style.left=x+'px';window.__cur.style.top=y+'px'}", [cx, cy]); self.pg.mouse.move(cx, cy); self.frame()
        self.pos = (x, y)
    def click(self, sel=None, hold=0.5):
        if sel:
            b = self.pg.locator(sel).first.bounding_box(); self.move(b["x"]+b["width"]/2, b["y"]+min(b["height"]/2, 24))
        self.pg.evaluate("()=>{window.__cur.style.transform='translate(-3px,-2px) scale(.8)'}"); self.hold(0.08)
        self.pg.mouse.click(*self.pos); self.pg.evaluate("()=>{window.__cur.style.transform='translate(-3px,-2px)'}"); self.hold(hold)
    def type(self, sel, text, cps=14):
        self.click(sel, 0.2)
        for ch in text: self.pg.keyboard.type(ch); self.hold(1/cps)
    def close(self):
        self.ff.stdin.close(); self.ff.wait(); print(self.path.name, self.n/FPS, "s")

with sync_playwright() as p:
    b = p.chromium.launch(); ctx = b.new_context(viewport={"width":1920,"height":1080}, device_scale_factor=1); pg = ctx.new_page()
    pg.goto("http://localhost:3000/login"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(800); pg.evaluate(CURSOR)
    f = Film(pg, out_login); f.hold(1.2)
    f.type("#user", "r.verma"); f.hold(0.3); f.type("#password", "Correct-Horse-Battery-9", 18); f.hold(0.5)
    f.click("button.login-btn", 0.3); pg.wait_for_url("http://localhost:3000/", timeout=15000); pg.wait_for_load_state("networkidle"); pg.evaluate(CURSOR); f.hold(1.5); f.close()
    f = Film(pg, out_console); f.hold(2.5)
    # tour: header → incident list → the swarm's findings → attack path
    f.move(150, 150, .8); f.hold(1.2)
    f.click("button.incident >> nth=1", 2.4)
    f.click("button.incident >> nth=0", 1.4)
    for sel in [".sig >> nth=0", ".sig >> nth=2", ".sig >> nth=4", ".sig >> nth=7"]:
        loc = pg.locator(sel)
        if loc.count():
            bb = loc.first.bounding_box()
            if bb: f.move(bb["x"]+60, bb["y"]+bb["height"]/2, .7); f.hold(1.1)
    f.move(1700, 540, .9); f.hold(2.0)
    # Agent Q: hover (mood tooltip), drag it out of the corner, tap to open, ask why, close
    q = pg.locator(".qm").first
    if q.count():
        bb = q.bounding_box(); cx, cy = bb["x"]+bb["width"]/2, bb["y"]+bb["height"]/2
        f.move(cx, cy, .8); f.hold(1.4)
        pg.mouse.down()
        for (tx, ty) in [(cx-200, cy-120), (cx-420, cy-260)]:
            f.move(tx, ty, .6)
        pg.mouse.up(); f.hold(.8)
        f.click(None, 0.9)                       # tap → the drawer opens beside it
        chip = pg.locator(".aq-chip").first
        if chip.count(): f.click(".aq-chip >> nth=0", 2.6)
        pg.keyboard.press("Escape"); f.hold(.6)
    # scroll the blast map / cards into view, then approve the first pending action with a rationale
    card = pg.locator(".action-card").first
    if card.count():
        card.scroll_into_view_if_needed(); f.hold(0.6)
        inp = pg.locator(".action-card input.btn").first
        if inp.count():
            f.type(".action-card input.btn >> nth=0", "Confirmed with network team — isolate while we review the session.", 22); f.hold(0.5)
            f.click(".action-card .btn-approve >> nth=0", 3.0)
    f.click("button.logout", 0.6); pg.wait_for_url("**/login", timeout=15000); pg.wait_for_load_state("networkidle"); pg.evaluate(CURSOR); f.hold(0.8)
    f.type("#user", "p.sharma"); f.type("#password", "Analyst-Only-Pass-77", 18); f.click("button.login-btn", 0.3)
    pg.wait_for_url("http://localhost:3000/", timeout=15000); pg.wait_for_load_state("networkidle"); pg.evaluate(CURSOR); f.hold(1.0)
    f.click("button.incident >> nth=0", 1.0)
    vo = pg.locator(".viewonly").first
    if vo.count(): vo.scroll_into_view_if_needed(); f.hold(.5); bb = vo.bounding_box(); f.move(bb["x"]+bb["width"]/2, bb["y"]+10); f.hold(3.0)
    f.close(); b.close()
