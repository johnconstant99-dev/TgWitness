"""Linux acceptance: actual sandboxed Chromium, Xvfb, FFmpeg and isolated networking."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="tgwitness-official-check")
    parser.add_argument("--direct", action="store_true", help="Also exercise explicit direct access to the real public login page")
    args = parser.parse_args()
    # The fixture is synthetic; its public DOM boundaries match the reviewed adapter.
    import importlib.util
    spec = importlib.util.spec_from_file_location("official_test", ROOT / "addons/capture/tests/test_official.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    script = "DIRECT = " + repr(args.direct) + "\nFIXTURE = " + repr(module.FIXTURE) + "\n" + r'''
import asyncio, importlib.util, json, socket, time, zipfile
from pathlib import Path
from tgwitness_capture.official import OfficialBrowser, OfficialOptions
from tgwitness_capture.journal import Journal
from tgwitness_capture.video import VideoCapture
from tgwitness_capture.export import export_zip
from tgwitness_capture.verify import verify_zip
assert importlib.util.find_spec('telethon') is None
assert importlib.util.find_spec('pyrogram') is None
for host, family in [('1.1.1.1', socket.AF_INET), ('2606:4700:4700::1111', socket.AF_INET6)]:
    if DIRECT:
        break
    with socket.socket(family, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        try:
            stream.connect((host,443))
        except OSError:
            pass
        else:
            raise AssertionError('Direct external network access is available')
async def main():
    if DIRECT:
        live_journal = Journal('/tmp/live-login-check')
        live = OfficialBrowser(OfficialOptions(egress='direct', drand=False), live_journal)
        try:
            await live.open()
            for _ in range(60):
                if await live.login_state() == 'qr':
                    break
                await asyncio.sleep(.5)
            assert await live.login_state() == 'qr', 'Real official QR login did not load'
            assert live.exit_ip
            print('PASS: explicit direct route and real official Telegram QR login page; no account login')
        finally:
            await live.close()
            live_journal.close()
    journal=Journal('/tmp/check-records')
    route_options = {'egress':'direct'} if DIRECT else {'proxy_server':'http://127.0.0.1:9'}
    browser=OfficialBrowser(OfficialOptions(**route_options,drand=False),journal)
    real_route=browser._route
    async def route(original):
        class FixtureRoute:
            request=original.request
            async def continue_(self):
                await original.fulfill(status=200,content_type='text/html',body=FIXTURE)
            async def abort(self,error):
                await original.abort(error)
        await real_route(FixtureRoute())
    async def probe():
        browser.exit_ip='203.0.113.7'
        browser.checked_route=time.monotonic()
    browser._route=route
    browser.check_route=probe
    video=VideoCapture(journal,['-f','x11grab','-framerate','12','-video_size','1280x720','-i',':99.0'],timestamp_overlay=True)
    try:
        await browser.open()
        chats=await browser.chats()
        await browser.select_chat(chats[0]['handle'])
        await browser.arm()
        video.start()
        await browser.page.locator('#send').dispatch_event('click')
        assert await browser.page.evaluate('window.sent')==0
        for _ in range(26):
            await asyncio.sleep(.5)
            video.poll()
            assert video.process is not None, video.error
        metadata,artifacts,at=await browser.capture(journal,{'screenshots':True,'pages':True},60,True)
        journal.append('capture.saved',metadata,artifacts,at)
        await asyncio.to_thread(video.stop)
        await browser.pause()
        await browser.close()
        journal.append('official.finished',{'logout_confirmed':False,'profile_context_closed':True})
        export_zip(journal,Path('/tmp/check.zip'))
        checked=verify_zip('/tmp/check.zip',journal.fingerprint)
        assert checked['official']['video_segments']>=2
        assert checked['official']['reasons']==['logout_unconfirmed']
        from tgwitness.sealed_package import connection, package
        from tgwitness.sealed_crypto import keypair, decrypt_file
        recipient=keypair()
        config={'client':'official_web','recipient':recipient['recipient'],'token':'a'*43,'context':{'synthetic':True}}
        connection(config,'https://fixture.trycloudflare.com','/tmp/connection.tgwsealed')
        decrypt_file('/tmp/connection.tgwsealed','/tmp/connection.json',recipient)
        assert json.loads(Path('/tmp/connection.json').read_bytes())['url'].endswith('#access='+'a'*43)
        out=Path('/tmp/delivery'); out.mkdir()
        Path('/tmp/check.zip').replace(out/'evidence.zip')
        (out/'result.json').write_text('{"phase":"sealed"}')
        (out/'attestation.jsonl').write_text('synthetic test only; not GitHub attestation')
        package(config,out,out/'attestation.jsonl')
        decrypt_file(out/'delivery.tgwsealed','/tmp/delivery.zip',recipient)
        with zipfile.ZipFile('/tmp/delivery.zip') as handoff:
            assert handoff.read('evidence.zip')==(out/'evidence.zip').read_bytes()
        print('PASS: Chromium sandbox, '+('explicit direct route' if DIRECT else 'denied IPv4/IPv6 egress')+', guarded DOM, Xvfb video with overlay, signed segments, standalone verification, encrypted connection and evidence delivery roundtrip')
    finally:
        video.abort()
        await browser.close()
        journal.close()
asyncio.run(main())
'''
    network = "official-check-" + uuid.uuid4().hex[:12]
    subprocess.run(["docker", "network", "create", *([] if args.direct else ["--internal"]), network], check=True, capture_output=True)
    try:
        result = subprocess.run(["docker", "run", "--rm", "--init", "-i", "--network", network,
                        "--user", str(os.getuid()) + ":" + str(os.getgid()), "--read-only", "--cap-drop=ALL",
                        "--security-opt=no-new-privileges", "--security-opt", "seccomp=" + str(ROOT / "addons/capture/deploy/official-seccomp.json"),
                        "--tmpfs", "/tmp:rw,nosuid,nodev,size=1g", "--shm-size=1g", "--pids-limit=512", "--memory=4g",
                        args.image, "python", "-"], input=script, text=True, timeout=180,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        print(result.stdout)
        if result.returncode or "PASS: Chromium sandbox" not in result.stdout:
            raise RuntimeError("Official container acceptance did not complete")
    finally:
        subprocess.run(["docker", "network", "rm", network], capture_output=True, check=False)


if __name__ == "__main__":
    main()
