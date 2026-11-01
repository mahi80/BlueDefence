import json, subprocess, os, base64
from pathlib import Path
from playwright.sync_api import sync_playwright
here = Path(__file__).parent
meta = json.load(open(here/"meta.json")); LEAD, TAIL, FPS = 0.6, 1.0, 30
sc = [round(LEAD+m["dur"]+TAIL,3) for m in meta]
FOOTAGE = {6: here/"ui"/"login.mp4", 7: here/"ui"/"console.mp4"}    # 1-based scene → clip, overlaid at (180,316) 1560x878
clips = here/"clips2"; clips.mkdir(exist_ok=True)
def enc(path):
    return subprocess.Popen(["ffmpeg","-y","-loglevel","error","-f","image2pipe","-vcodec","mjpeg","-framerate",str(FPS),"-i","-","-c:v","libx264","-preset","medium","-crf","19","-pix_fmt","yuv420p",str(path)], stdin=subprocess.PIPE)
with sync_playwright() as p:
    b=p.chromium.launch(); pg=b.new_page(viewport={"width":1920,"height":1080})
    pg.goto(f"file://{here/'sim.html'}"); pg.wait_for_timeout(2500); pg.evaluate("s=>{window.SCENES=s}", sc)
    cdp = pg.context.new_cdp_session(pg); t0 = 0.0
    for i, seg in enumerate(sc, 1):
        tmp = clips/f"v{i:02d}.tmp.mp4"; ff = enc(tmp); N = int(round(seg*FPS))
        for f in range(N):
            pg.evaluate("t=>window.render(t)", t0 + f/FPS)
            ff.stdin.write(base64.b64decode(cdp.send("Page.captureScreenshot", {"format":"jpeg","quality":92})["data"]))
        ff.stdin.close(); ff.wait(); assert ff.returncode == 0; os.replace(tmp, clips/f"v{i:02d}.mp4"); t0 += seg; print("scene", i, seg, flush=True)
    b.close()
parts=[]
for i, seg in enumerate(sc, 1):
    v = clips/f"v{i:02d}.mp4"; a = here/"vo"/f"scene{i:02d}.wav"; out = clips/f"c{i:02d}.mp4"; tmp = clips/f"c{i:02d}.tmp.mp4"
    af = f"[1:a]adelay={int(LEAD*1000)}|{int(LEAD*1000)},apad,atrim=0:{seg},afade=t=out:st={seg-.3:.3f}:d=0.3[a]"
    if i in FOOTAGE:
        # footage fades in at 1.0 s, plays once, holds its last frame to the end of the scene
        vf = (f"[2:v]scale=1200:675:flags=lanczos,tpad=stop_mode=clone:stop_duration=600,trim=0:{seg-1.0},setpts=PTS-STARTPTS,fade=t=in:st=0:d=0.5,format=yuva420p[fg];"
              f"[0:v][fg]overlay=360:300:enable='gte(t,1.0)':shortest=0:eof_action=repeat,format=yuv420p[v]")
        cmd = ["ffmpeg","-y","-loglevel","error","-i",str(v),"-i",str(a),"-itsoffset","1.0","-i",str(FOOTAGE[i]),"-filter_complex",vf+";"+af,"-map","[v]","-map","[a]","-t",f"{seg:.3f}"]
    else:
        cmd = ["ffmpeg","-y","-loglevel","error","-i",str(v),"-i",str(a),"-filter_complex",af,"-map","0:v","-map","[a]","-t",f"{seg:.3f}"]
    cmd += ["-c:v","libx264","-preset","medium","-crf","19","-pix_fmt","yuv420p","-c:a","aac","-b:a","160k","-ar","44100",str(tmp)]
    subprocess.run(cmd, check=True); os.replace(tmp, out); parts.append(out); print("mux", i, flush=True)
(here/"list2.txt").write_text("".join(f"file '{p}'\n" for p in parts))
final = here/"BlueDefence-how-it-works.mp4"
subprocess.run(["ffmpeg","-y","-loglevel","error","-f","concat","-safe","0","-i",str(here/"list2.txt"),"-c","copy","-movflags","+faststart",str(final)], check=True)
print(subprocess.check_output(["ffprobe","-v","error","-show_entries","format=duration,size","-of","csv=p=0",str(final)]).decode())
