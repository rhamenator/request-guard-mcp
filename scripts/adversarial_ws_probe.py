#!/usr/bin/env python3
"""Bounded WebSocket adversarial probe for an authorized Request Guard lab."""
import argparse
import base64
import json
import os
import socket
import struct
import sys

INITIALIZE_MESSAGE = json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'kali-probe','version':'1'}}})
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=8085)
parser.add_argument("--max-request-bytes", type=int, help="enable bounded frame-limit tests with this configured server limit (max 65536)")
args = parser.parse_args()
if args.max_request_bytes is not None and not len(INITIALIZE_MESSAGE.encode()) <= args.max_request_bytes <= 65536:
    parser.error(f"--max-request-bytes must be from {len(INITIALIZE_MESSAGE.encode())} to 65536 so initialize fits the configured limit")
HOST = args.host
PORT = args.port
TOKEN = sys.stdin.readline().strip()
if len(TOKEN) < 32:
    parser.error("read a lab bearer token of at least 32 characters from stdin")
def recv_exact(sock,n):
    out=b''
    while len(out)<n:
        chunk=sock.recv(n-len(out))
        if not chunk: raise EOFError('socket closed')
        out+=chunk
    return out
def connect(token=None):
    sock=socket.create_connection((HOST,PORT),timeout=5)
    sock.settimeout(5)
    key=base64.b64encode(os.urandom(16)).decode()
    headers=[f'GET /mcp HTTP/1.1',f'Host: {HOST}:{PORT}','Upgrade: websocket','Connection: Upgrade',f'Sec-WebSocket-Key: {key}','Sec-WebSocket-Version: 13','Sec-WebSocket-Protocol: mcp']
    if token is not None: headers.append('Authorization: Bearer '+token)
    sock.sendall(('\r\n'.join(headers)+'\r\n\r\n').encode())
    raw=b''
    while b'\r\n\r\n' not in raw:
        chunk=sock.recv(4096)
        if not chunk: raise ConnectionError('peer closed during WebSocket handshake')
        raw+=chunk
    return sock,int(raw.split(b' ',2)[1])
def send_text(sock,content):
    send_frame(sock,1,True,content.encode())
def send_frame(sock,opcode,final,payload):
    mask=os.urandom(4)
    first=(0x80 if final else 0)|opcode
    if len(payload)<126: header=bytes([first,0x80|len(payload)])
    elif len(payload)<65536: header=bytes([first,0xfe])+struct.pack('!H',len(payload))
    else: header=bytes([first,0xff])+struct.pack('!Q',len(payload))
    sock.sendall(header+mask+bytes(b^mask[i%4] for i,b in enumerate(payload)))
def recv_frame(sock):
    a,b=recv_exact(sock,2);length=b&127
    if length==126:length=struct.unpack('!H',recv_exact(sock,2))[0]
    elif length==127:length=struct.unpack('!Q',recv_exact(sock,8))[0]
    if b&128: mask=recv_exact(sock,4)
    else: mask=None
    if length>2_000_000:raise ValueError('response too large')
    payload=recv_exact(sock,length)
    if mask:payload=bytes(v^mask[i%4] for i,v in enumerate(payload))
    return a&15,payload
out=[]
def check(name,passed,detail):
    out.append(passed);print(json.dumps({'case':name,'pass':passed,'detail':detail}))
for name,auth,expected in [('ws_missing_auth',None,401),('ws_wrong_auth',TOKEN+'wrong',403)]:
    sock,status=connect(auth);sock.close();check(name,status==expected,status)
sock,status=connect(TOKEN)
check('ws_authorized_upgrade',status==101,status)
if status==101:
    send_text(sock,INITIALIZE_MESSAGE)
    op,payload=recv_frame(sock);value=json.loads(payload)
    check('ws_initialize',op==1 and value.get('result',{}).get('protocolVersion')=='2025-06-18',{'opcode':op,'id':value.get('id')})
    send_text(sock,'{broken')
    op,payload=recv_frame(sock);value=json.loads(payload)
    check('ws_malformed_json',op==1 and value.get('error',{}).get('code')==-32700,{'opcode':op,'code':value.get('error',{}).get('code')})
    for name,envelope in [
        ('ws_wrong_jsonrpc_version',{'jsonrpc':'1.0','id':2,'method':'ping'}),
        ('ws_scalar_params',{'jsonrpc':'2.0','id':2,'method':'ping','params':42}),
    ]:
        send_text(sock,json.dumps(envelope))
        op,payload=recv_frame(sock);value=json.loads(payload)
        check(name,op==1 and value.get('error',{}).get('code')==-32600 and value.get('id') is None,{'opcode':op,'code':value.get('error',{}).get('code')})
    send_text(sock,json.dumps({'jsonrpc':'2.0','id':3,'method':'tools/list'}))
    op,payload=recv_frame(sock);value=json.loads(payload)
    names={tool['name'] for tool in value.get('result',{}).get('tools',[])}
    check('ws_tools_list',op==1 and {'classify','explain'}<=names,{'opcode':op,'tools':len(names)})
    sock.close()
if args.max_request_bytes is not None:
    for name,fragmented in [('ws_oversized_frame',False),('ws_oversized_fragmented_message',True)]:
        sock,status=connect(TOKEN)
        if status==101:
            oversized=b'x'*(args.max_request_bytes+1)
            if fragmented:
                midpoint=len(oversized)//2
                send_frame(sock,1,False,oversized[:midpoint])
                send_frame(sock,0,True,oversized[midpoint:])
            else:
                send_frame(sock,1,True,oversized)
            try:
                op,payload=recv_frame(sock)
                close_code=struct.unpack('!H',payload[:2])[0] if op==8 and len(payload)>=2 else None
                closed_without_frame=False
            except (EOFError,ConnectionResetError):
                close_code=None
                op=None
                closed_without_frame=True
            check(name,op==8 or closed_without_frame,{'upgrade':status,'opcode':op,'close_code':close_code,'hard_close':closed_without_frame})
        else:
            check(name,False,{'upgrade':status})
        sock.close()
    sock,status=connect(TOKEN)
    if status==101:
        send_text(sock,json.dumps({'jsonrpc':'2.0','id':4,'method':'ping'}))
        op,payload=recv_frame(sock);value=json.loads(payload)
        check('ws_after_oversize_recovers',op==1 and value.get('result')=={}, {'upgrade':status,'opcode':op})
    else:
        check('ws_after_oversize_recovers',False,{'upgrade':status})
    sock.close()
print(json.dumps({'passed':sum(out),'total':len(out)}))
sys.exit(0 if all(out) else 1)
