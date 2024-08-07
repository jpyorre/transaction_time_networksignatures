from fastapi import FastAPI, UploadFile, Request, Response, HTTPException, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from lib.signature_processor import SignatureGenerator
from lib.pcap_processor import PcapProcessor
from lib.yaraPcap import YaraPcapProcessor
import os, json

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/lib", StaticFiles(directory="lib"), name="lib")
templates = Jinja2Templates(directory="templates")

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get('/yarapcap', response_class=HTMLResponse)
async def yarapcap(request: Request):
    return templates.TemplateResponse("yarapcap.html", {"request": request})

@app.post('/process_yara_pcap')
async def process_yara_pcap(file: UploadFile = File(...)):
    filename = file.filename
    file_path = os.path.join('upload', filename)
    with open(file_path, "wb") as f:
        f.write(file.file.read())
    rules = 'signatures/yararules/Emotet.yar'
    try:
        processor = YaraPcapProcessor(file_path, rules)
        results = processor.main()
        os.remove(file_path)
        return HTMLResponse("</br>".join(results))
    except Exception as e:
        return HTMLResponse(f"Failed to process YARA PCAP: {e}")

@app.get('/analyzepcap', response_class=HTMLResponse)
async def analyzepcap(request: Request):
    return templates.TemplateResponse('analyzepcap.html', {"request": request})

@app.post('/analyze_pcap')
async def analyze_pcap(file: UploadFile = File(...)):
    filename = file.filename
    file_path = os.path.join('upload', filename)
    try:
        with open(file_path, "wb") as f:
            f.write(file.file.read())
        
        ppcap = PcapProcessor()
        results = json.loads(ppcap.start(file_path))
        
        return JSONResponse(results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@app.get('/signatures', response_class=HTMLResponse)
async def signatures(request: Request):
    try:
        with open('signatures/networkrules/signatures.json') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                data = {}
    except:
        data = {}
    return templates.TemplateResponse("signatures.html", {"request": request, "json_data": data})

@app.post('/create_signature')
async def create_signature(file: UploadFile = File(...)):
    filename = file.filename
    signatures_dir = 'signatures/networkrules'
    file_path = os.path.join(signatures_dir, filename)
    with open(file_path, "wb") as f:
        f.write(file.file.read())
    sig = SignatureGenerator(filename)
    percentages_rounded_with_no_zeros = sig.main(file_path)
    sig.make_signature(percentages_rounded_with_no_zeros, filename)
    os.remove(file_path)
    with open('signatures/networkrules/signatures.json') as f:
        updated_data = json.load(f)
        if not isinstance(updated_data, dict):
            updated_data = {}
    return JSONResponse({"updated_data": updated_data, "filename": filename})

@app.post('/delete_signatures')
async def delete_signatures():
    signatures_file = 'signatures/networkrules/signatures.json'
    if os.path.exists(signatures_file):
        with open(signatures_file, 'w') as f:
            json.dump({}, f)
    return JSONResponse({"message": "All signatures deleted"})

@app.get('/progress')
async def get_progress():
    progress_file = 'progress.json'
    if not os.path.exists(progress_file):
        return JSONResponse({'progress': 0})
    with open(progress_file, 'r') as f:
        progress = json.load(f)
    return JSONResponse(progress)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
