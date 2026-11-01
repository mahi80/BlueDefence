import json, subprocess, os
from pathlib import Path
from playwright.sync_api import sync_playwright
here = Path(__file__).parent
meta = json.load(open(here/"meta.json")); LEAD, TAIL, FPS = 0.6, 1.0, 30
sc = [round(LEAD+m["dur"]+TAIL,3) for m in meta]
total = sum(sc); N = int(round(total*FPS))
tmp, out = here/"sim-video.tmp.mp4", here/"sim-video.mp4"
ff = subprocess.Popen(["ffmpeg","-y","-loglevel","error","-f","image2pipe","-vcodec","mjpeg","-framerate",str(FPS),"-i","-",
                       "-c:v","libx264","-preset","medium","-crf","19","-pix_fmt","yuv420p","-movflags","+faststart",str(tmp)], stdin=subprocess.PIPE)
with sync_playwright() as p:
    b=p.chromium.launch(); pg=b.new_page(viewport={"width":1920,"height":1080})
    pg.goto(f"file://{here/'sim.html'}"); pg.wait_for_timeout(2500)
    pg.evaluate("s=>{window.SCENES=s}", sc)
    cdp = pg.context.new_cdp_session(pg)
    import base64
    for f in range(N):
        pg.evaluate("t=>window.render(t)", f/FPS)
        r = cdp.send("Page.captureScreenshot", {"format":"jpeg","quality":92})
        ff.stdin.write(base64.b64decode(r["data"]))
        if f % 600 == 0: print(f"{f}/{N}", flush=True)
    b.close()
ff.stdin.close(); ff.wait()
assert ff.returncode == 0; os.replace(tmp, out)
# audio: concat the per-scene wavs with lead/tail padding, then mux
parts=[]
for m in meta:
    i=m["scene"]; seg=sc[i-1]; w=here/"vo"/f"pad{i:02d}.wav"
    subprocess.run(["ffmpeg","-y","-loglevel","error","-i",str(here/"vo"/f"scene{i:02d}.wav"),"-af",f"adelay={int(LEAD*1000)}|{int(LEAD*1000)},apad,atrim=0:{seg}","-ar","44100","-ac","1",str(w)],check=True); parts.append(w)
(here/"alist.txt").write_text("".join(f"file '{p}'\n" for p in parts))
subprocess.run(["ffmpeg","-y","-loglevel","error","-f","concat","-safe","0","-i",str(here/"alist.txt"),"-c","copy",str(here/"narration.wav")],check=True)
final=here/"BlueDefence-how-it-works.mp4"
subprocess.run(["ffmpeg","-y","-loglevel","error","-i",str(out),"-i",str(here/"narration.wav"),"-map","0:v","-map","1:a","-c:v","copy","-c:a","aac","-b:a","160k","-shortest","-movflags","+faststart",str(final)],check=True)
print(subprocess.check_output(["ffprobe","-v","error","-show_entries","format=duration,size","-of","csv=p=0",str(final)]).decode())
