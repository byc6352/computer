unit uSocket;

interface
//************************windows����**************************************
const
  user32    = 'USER32.dll';
  //-------------------------------------------
  con_CON_VER=1001; //ͨѶЭ��汾
  con_Encrpt=1;
type
  BOOL = LongBool;
  DWORD = LongWord;

//************************socket ����****************************
type
  u_int = Integer;
  TSocket = u_int;
  u_short = Word;
  u_char = Char;
  u_long = Longint;
const
  winsocket = 'WSock32.dll';
  SOCKET_ERROR      = -1;
  INVALID_SOCKET    = TSocket(NOT(0));
  WSADESCRIPTION_LEN     =   256;
  WSASYS_STATUS_LEN      =   128;
  AF_INET         = 2;
  SOCK_STREAM     = 1;               { stream socket }

  SOL_SOCKET      = $ffff;          {options for socket level }
  SO_LINGER       = $0080;          { linger on close if data present }
  SO_SNDTIMEO     = $1005;          { send timeout }
  SO_RCVTIMEO     = $1006;          { receive timeout }
  WSAECONNRESET   =10054;
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
          sin_zero: array[0..7] of ansiChar);
      1: (sa_family: u_short;
          sa_data: array[0..13] of ansiChar)
  end;
  TSockAddrIn = sockaddr_in;
  PSOCKADDR = ^TSockAddr;
  TSockAddr = sockaddr_in;

  PWSAData = ^TWSAData;
  WSAData = record // !!! also WSDATA
    wVersion: Word;
    wHighVersion: Word;
    szDescription: array[0..WSADESCRIPTION_LEN] of ansiChar;
    szSystemStatus: array[0..WSASYS_STATUS_LEN] of ansiChar;
    iMaxSockets: Word;
    iMaxUdpDg: Word;
    lpVendorInfo: PansiChar;
  end;
  TWSAData = WSAData;
  PHostEnt = ^THostEnt;
  {$EXTERNALSYM hostent}
  hostent = record
    h_name: PansiChar;
    h_aliases: ^PansiChar;
    h_addrtype: Smallint;
    h_length: Smallint;
    case Byte of
      0: (h_addr_list: ^PansiChar);
      1: (h_addr: ^PansiChar)
  end;
  THostEnt = hostent;
  //2006-04-25
  linger = record
    l_onoff: u_short;
    l_linger: u_short;
  end;
  timeval = record
    tv_sec: Longint;
    tv_usec: Longint;
  end;
//************************�ҵ� ����****************************
type
  pSvrAddr=^stSvrAddr;
  stSvrAddr=packed record
    port:Word;
    case flg:byte of
    0:(IP:array[0..15] of ansiChar);
    1:(DN:array[0..30] of ansiChar);
  end;
  POrdHeader=^stOrdHeader;
  stOrdHeader=packed record
    Version:DWORD;
    Encrpt:DWORD;
    Order:DWORD;
    DataSize:DWORD;
    Data:pointer;
  end;
  //---------------------------------------------------------
//***********************socket api***********************************
function recv(s: TSocket; var Buf; len, flags: Integer): Integer; stdcall;
function send(s: TSocket; var Buf; len, flags: Integer): Integer; stdcall;
function connect(s: TSocket; var name: TSockAddr; namelen: Integer): Integer; stdcall;
function closesocket(s: TSocket): Integer; stdcall;
function WSACleanup: Integer; stdcall;
function socket(af, Struct, protocol: Integer): TSocket; stdcall;
function WSAStartup(wVersionRequired: word; var WSData: TWSAData): Integer; stdcall;
function htons(hostshort: u_short): u_short; stdcall;
function inet_addr(cp: PansiChar): u_long; stdcall; {PInAddr;}  { TInAddr }
function gethostbyname(name: PansiChar): PHostEnt; stdcall;

function setsockopt(s: TSocket; level, optname: Integer; optval: PansiChar;
  optlen: Integer): Integer; stdcall;
function WSAGetLastError: Integer; stdcall;
//***********************windows api*************************************
procedure ZeroMemory(Destination: Pointer; Length: DWORD);
function wsprintf(Output: PansiChar; Format: PansiChar): Integer; stdcall;


//***********************�ַ�������*************************************
function _wsprintf(lpOut: PansiChar; lpFmt: PansiChar; lpVars: Array of Const):Integer; assembler;
//***********************�ҵĺ���*****************************************
function InitAddr(sa:stSvrAddr;var addr:sockaddr_in):bool;stdcall;
function HostToIP(hostName:pansiChar):in_addr;stdcall;
function InitSocket(var hSocket:integer):bool;stdcall;
procedure FreeSocket(var hSocket:integer);stdcall; //out
function ConnectServer(var hSocket:integer;sa:stSvrAddr):bool;stdcall; //out
function RecvBuf(hSocket:integer;p:pointer;len:DWORD):bool;stdcall;
function SendBuf(socket:integer;p:pointer;size:DWORD):bool;stdcall;
function GetLocalIP(IP:pansiChar):bool;stdcall;
function RecvNon(hSocket:integer;p:pointer;len:integer):integer;stdcall;
function InitOrdHeader(poh:POrdHeader):BOOL;
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

function setsockopt;        external    winsocket name 'setsockopt';
function WSAGetLastError;        external    winsocket name 'WSAGetLastError';
//***********************�ַ�������*************************************
function _wsprintf(lpOut:pansiChar;lpFmt:pansiChar;lpVars:array of const):integer;assembler;
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
//*********************�ҵĺ���****************************************
function RecvNon(hSocket:integer;p:pointer;len:integer):integer;stdcall;
begin
  result:=recv(hSocket,p^,len,0);
end;
function SendBuf(socket:integer;p:pointer;size:DWORD):bool;stdcall;
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
    //if i=SOCKET_ERROR then exit;   2015-9-5
    if (i=SOCKET_ERROR) and (WSAGetLastError = WSAECONNRESET) then exit;
    len:=len-i;
    pp:=pointer(DWORD(pp)+DWORD(i));
  end;//while
  result:=true;
end;
function RecvBuf(hSocket:integer;p:pointer;len:DWORD):bool;stdcall;
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
    if (err=SOCKET_ERROR) or (err=0) then exit;  //2015
    //if (err=SOCKET_ERROR) or (err=0) then exit;
    k:=k-err;
    pp:=pointer(dword(pp)+dword(err));
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
  err:=connect(hSocket,addr,sizeof(addr));//����
  if err<>0 then FreeSocket(hSocket);
  result:=err=0;
end;
procedure FreeSocket(var hSocket:integer);stdcall;
begin
  if hSocket<>0 then  closesocket(hSocket);
  //WSACleanup();//��ֹWS2_32.DLL��ʹ��
  hSocket:=0;
end;
{
��������:��ʼ��Socket
��ڲ���:hSocket:Socket���
���ڲ���:����ֵ:�ɹ���������True,���򷵻�False
��������:
�޸ļ�¼:���ӳ�ʱʱ��6����
2006-04-25
Author:byc
}
function InitSocket(var hSocket:integer):bool;stdcall;
var
  wsadata: TWSAData;
  err:integer;
  //t:linger;
  //timeout: timeval;
  tv:longint;
begin
  result:=false;
  err:=WSAStartup($0202,wsadata);
  if  err<>0 then
  begin //��ʼ��WS2_32.DLL
    //showmessage('��ʼ��ws_32.dllʧ��!');
    WSACleanup();//��ֹWS2_32.DLL��ʹ��
    exit;
  end;//if
  hSocket:=socket(AF_INET, SOCK_STREAM, 0);
  //����socket
  if hSocket=INVALID_SOCKET then
  begin
    //ShowMessage('����SOCKETʧ��!');
    hSocket:=0;
    WSACleanup();
    exit;
  end;//if socket1=SOCKET_ERROR then
  {
  t.l_onoff:=1;
  t.l_linger:=0;
  //�ر�socket�������ͷ���Դ
  err:=setsockopt(hSocket,SOL_SOCKET,SO_LINGER,@t,sizeof(t));
  if err=SOCKET_ERROR then
  begin
    FreeSocket(hSocket);
    exit;
  end;
  }
  //set recv and send timeout
  tv:=6*60*1000;
  //tv:=60000;//����
  err:=setsockopt(hSocket,SOL_SOCKET,SO_SNDTIMEO,@tv,sizeof(timeval));
  if err=SOCKET_ERROR then
  begin
    FreeSocket(hSocket);
    exit;
  end;
  err:=setsockopt(hSocket,SOL_SOCKET,SO_RCVTIMEO,@tv,sizeof(timeval));
  if err=SOCKET_ERROR then
  begin
    FreeSocket(hSocket);
    exit;
  end;
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
function HostToIP(hostName:pansiChar):in_addr;stdcall;
var
  hostEnt : PHostEnt;
  addr:pansiChar;
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
function GetLocalIP(IP:pansiChar):bool;stdcall;
var
  wd:WSAdata;
  err:integer;
  phe:PhostEnt;
  addr:pansiChar;
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
function InitOrdHeader(poh:POrdHeader):BOOL;
begin
  ZeroMemory(poh,sizeof(stOrdHeader));
  poh^.Version:=con_CON_VER;
  poh^.Encrpt:=con_Encrpt;
  result:=true;
end;
//------------------------------------------------------------------
end.