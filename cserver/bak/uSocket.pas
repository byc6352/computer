unit uSocket;

interface
//************************windows定义**************************************
const
  user32    = 'user32.dll';
type
  BOOL = LongBool;
  DWORD = LongWord;

//************************socket 定义****************************
type
  u_int = Integer;
  TSocket = u_int;
  u_short = Word;
  u_char = Char;
  u_long = Longint;
const
  winsocket = 'wsock32.dll';
  SOCKET_ERROR      = -1;
  INVALID_SOCKET    = TSocket(NOT(0));
  WSADESCRIPTION_LEN     =   256;
  WSASYS_STATUS_LEN      =   128;
  AF_INET         = 2;
  SOCK_STREAM     = 1;               { stream socket }
type
  SunB = packed record
    s_b1, s_b2, s_b3, s_b4: u_char;
  end;
  SunW = packed record
    s_w1, s_w2: u_short;
  end;
  PInAddr = ^TInAddr;
  in_addr = record
    case integer of
      0: (S_un_b: SunB);
      1: (S_un_w: SunW);
      2: (S_addr: u_long);
  end;
  TInAddr = in_addr;
  PSockAddrIn = ^TSockAddrIn;
  sockaddr_in = record
    case Integer of
      0: (sin_family: u_short;
          sin_port: u_short;
          sin_addr: TInAddr;
          sin_zero: array[0..7] of Char);
      1: (sa_family: u_short;
          sa_data: array[0..13] of Char)
  end;
  TSockAddrIn = sockaddr_in;
  PSOCKADDR = ^TSockAddr;
  TSockAddr = sockaddr_in;

  PWSAData = ^TWSAData;
  WSAData = record // !!! also WSDATA
    wVersion: Word;
    wHighVersion: Word;
    szDescription: array[0..WSADESCRIPTION_LEN] of Char;
    szSystemStatus: array[0..WSASYS_STATUS_LEN] of Char;
    iMaxSockets: Word;
    iMaxUdpDg: Word;
    lpVendorInfo: PChar;
  end;
  TWSAData = WSAData;
  PHostEnt = ^THostEnt;
  {$EXTERNALSYM hostent}
  hostent = record
    h_name: PChar;
    h_aliases: ^PChar;
    h_addrtype: Smallint;
    h_length: Smallint;
    case Byte of
      0: (h_addr_list: ^PChar);
      1: (h_addr: ^PChar)
  end;
  THostEnt = hostent;

//************************我的 定义****************************
type
  pSvrAddr=^stSvrAddr;
  stSvrAddr=packed record
    port:Word;
    case flg:byte of
    0:(IP:array[0..15] of char);
    1:(DN:array[0..30] of char);
  end;
//***********************windows api*************************************
procedure ZeroMemory(Destination: Pointer; Length: DWORD);
function wsprintf(Output: PChar; Format: PChar): Integer; stdcall;

//***********************socket api***********************************
function recv(s: TSocket; var Buf; len, flags: Integer): Integer; stdcall;
function send(s: TSocket; var Buf; len, flags: Integer): Integer; stdcall;
function connect(s: TSocket; var name: TSockAddr; namelen: Integer): Integer; stdcall;
function closesocket(s: TSocket): Integer; stdcall;
function WSACleanup: Integer; stdcall;
function socket(af, Struct, protocol: Integer): TSocket; stdcall;
function WSAStartup(wVersionRequired: word; var WSData: TWSAData): Integer; stdcall;
function htons(hostshort: u_short): u_short; stdcall;
function inet_addr(cp: PChar): u_long; stdcall; {PInAddr;}  { TInAddr }
function gethostbyname(name: PChar): PHostEnt; stdcall;
//***********************字符串函数*************************************
function _wsprintf(lpOut: PChar; lpFmt: PChar; lpVars: Array of Const):Integer; assembler;
//***********************我的函数*****************************************
function InitAddr(sa:stSvrAddr;var addr:sockaddr_in):bool;stdcall;
function HostToIP(hostName:pchar):in_addr;stdcall;
function InitSocket(var hSocket:integer):bool;stdcall;
procedure FreeSocket(var hSocket:integer);stdcall; //out
function ConnectServer(var hSocket:integer;sa:stSvrAddr):bool;stdcall; //out
function RecvBuf(hSocket:integer;p:pointer;len:integer):bool;stdcall;
function SendBuf(socket:integer;p:pointer;size:integer):bool;stdcall;
function GetLocalIP(IP:pchar):bool;stdcall;
function RecvNon(hSocket:integer;p:pointer;len:integer):integer;stdcall;
implementation
//***********************windows api*************************************
procedure ZeroMemory(Destination: Pointer; Length: DWORD);
begin
  FillChar(Destination^, Length, 0);
end;
function wsprintf; external user32 name 'wsprintfA';
//**********************socket api******************************************
function recv;              external    winsocket name 'recv';
function send;              external    winsocket name 'send';
function connect;           external    winsocket name 'connect';
function closesocket;       external    winsocket name 'closesocket';
function WSACleanup;        external     winsocket name 'WSACleanup';
function WSAStartup;        external     winsocket name 'WSAStartup';
function socket;            external    winsocket name 'socket';
function htons;             external    winsocket name 'htons';
function inet_addr;         external    winsocket name 'inet_addr';
function gethostbyname;     external    winsocket name 'gethostbyname';
//***********************字符串函数*************************************
function _wsprintf(lpOut:pchar;lpFmt:pchar;lpVars:array of const):integer;assembler;
var
  count:integer;
  v1,v2:integer;
asm
  mov v1,eax
  mov v2,edx
  mov eax,ecx
  mov ecx,[ebp+$08]
  inc ecx
  mov count,ecx
  dec ecx
  imul ecx,8
  add eax,ecx
  mov ecx,count
@@1:
  mov edx,[eax]
  push edx
  sub eax,8
  loop @@1

  push v2
  push v1

  call wsprintf

  mov ecx,count
  imul ecx,4
  add ecx,8
  add esp,ecx
end;
//*********************我的函数****************************************
function RecvNon(hSocket:integer;p:pointer;len:integer):integer;stdcall;
begin
  result:=recv(hSocket,p^,len,0);
end;
function SendBuf(socket:integer;p:pointer;size:integer):bool;stdcall;
var
  i,len:integer;
  pp:pointer;
begin
  result:=false;
  len:=size;
  pp:=p;
  while len>0 do
  begin
    i:=send(socket,pp^,len,0);
    if i=SOCKET_ERROR then exit;
    len:=len-i;
    pp:=pointer(dword(pp)+i);
  end;//while
  result:=true;
end;
function RecvBuf(hSocket:integer;p:pointer;len:integer):bool;stdcall;
var
  err,k:integer;
  pp:pointer;
begin
  result:=false;
  k:=len;
  pp:=p;
  while k>0 do
  begin
    err:=recv(hSocket,pp^,k,0);
    if (err=SOCKET_ERROR) or (err=0) then exit;
    k:=k-err;
    pp:=pointer(dword(pp)+err);
  end;
  result:=true;
end;
function ConnectServer(var hSocket:integer;sa:stSvrAddr):bool;stdcall;
var
  err:integer;
  addr:sockaddr_in;
begin
  result:=false;
  if not InitSocket(hSocket) then exit;
  InitAddr(sa,addr);
  err:=connect(hSocket,addr,sizeof(addr));//连接
  if err<>0 then
  begin
   closesocket(hSocket);
   hSocket:=0;
  end;
  result:=err=0;
end;
procedure FreeSocket(var hSocket:integer);stdcall;
begin
  closesocket(hSocket);
  WSACleanup();//终止WS2_32.DLL的使用
  hSocket:=0;
end;
function InitSocket(var hSocket:integer):bool;stdcall;
var
  wsadata: TWSAData;
  err:integer;
begin
  result:=false;
  err:=WSAStartup($0202,wsadata);
  if  err<>0 then
  begin //初始化WS2_32.DLL
    //showmessage('初始化ws_32.dll失败!');
    WSACleanup();//终止WS2_32.DLL的使用
    exit;
  end;//if
  hSocket:=socket(AF_INET, SOCK_STREAM, 0);
  //创建socket
  if hSocket=INVALID_SOCKET then
  begin
    //ShowMessage('创建SOCKET失败!');
    closesocket(hSocket);
    WSACleanup();
    exit;
  end;//if socket1=SOCKET_ERROR then
  result:=true;
end;
function InitAddr(sa:stSvrAddr;var addr:sockaddr_in):bool;stdcall;
begin
  result:=false;
  zeromemory(@addr,sizeof(addr));
  addr.sin_family:=AF_INET;
  addr.sin_port:=htons(sa.port);
  case sa.flg of
  0:begin
      addr.sin_addr.S_addr:=inet_addr(sa.IP);
    end;//0
  1:begin
      addr.sin_addr:=HostToIP(sa.DN);
    end;//1
  end;//case
  if addr.sin_addr.S_addr>0 then
    result:=true;
end;
function HostToIP(hostName:pchar):in_addr;stdcall;
var
  hostEnt : PHostEnt;
  addr:pchar;
  err:integer;
  wd:wsadata;
begin
  err:=WSAStartup($0202,WD);
  if err<>0 then exit;
  ZeroMemory(@result,sizeof(in_addr));
  hostEnt:=gethostbyname (hostName);
  if Assigned (hostEnt) then
  if Assigned (hostEnt^.h_addr_list) then
  begin
    addr := hostEnt^.h_addr_list^;
    if Assigned (addr) then
    begin
      result:=PInAddr(addr)^;
    end;// if Assigned (addr) then
  end;//if Assigned (hostEnt) then
  wsacleanup();
end;
function GetLocalIP(IP:pchar):bool;stdcall;
var
  wd:WSAdata;
  err:integer;
  phe:PhostEnt;
  addr:pchar;
  b0,b1,b2,b3:byte;
begin
  result:=false;
  err:=WSAStartup($101,wd);
  if err<>0 then begin wsaCleanup;exit;end;
  phe:=GetHostByName(nil);
  if phe=nil then begin wsaCleanup;exit;end;
  addr:=(phe^.h_addr)^;
  if addr=nil then begin wsaCleanup;exit;end;
  b0:=byte((addr+0)^);b1:=byte((addr+1)^);
  b2:=byte((addr+2)^);b3:=byte((addr+3)^);
  _wsprintf(IP,'%d.%d.%d.%d',[b0,b1,b2,b3]);
  wsaCleanup;
  result:=true;
end;
end.
