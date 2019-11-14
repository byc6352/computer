unit uDebug;

interface
uses windows;
const
  LOG_FILE:pchar='c:\svr\Server6Log.txt';
  LOG_DIR:pchar='c:\svr';
var
  test:boolean=true;

procedure EnableTest();
procedure Log(lpFmt: PChar; lpVars: Array of Const);overload;
procedure Log(str:PChar);overload;
procedure Log(str:PChar;Data:pointer;dwSize:DWORD);overload;
procedure GetAPIErr();overload;
function GetAPIErr(str:PChar):PChar;overload;
function _wsprintf(lpOut: PChar; lpFmt: PChar; lpVars: Array of Const):Integer; assembler;
function NowToStr(Str:pchar):Pchar;
implementation
procedure EnableTest();
var
  buf:array[0..255] of char;
  nSize:DWORD;
begin
  nSize:=sizeof(buf);
  if GetComputerName(buf,nSize) then
  begin
    buf[3]:=#0;
    if (lstrcmpi(buf,'BYC')=0)or(lstrcmpi(buf,'GZL')=0) then test:=true;
  end;
  //test:=true;
end;
procedure Log(str:PChar);
begin
  Log(str,['']);
end;
procedure Log(lpFmt: PChar; lpVars: Array of Const);
var
  hFile,NumOfWritten:cardinal;
  Len:integer;
  CRLF:array[0..2] of char;
  buf,str:array[0..1023] of char;
  strtime:array[0..127] of char;
begin
  if not test then exit;
  createdirectory(LOG_DIR,nil);
  hFile:=createfile(LOG_FILE,GENERIC_WRITE,FILE_SHARE_READ,nil,
                     OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
  if hFile=INVALID_HANDLE_VALUE then exit;
  setfilepointer(hFile,0,nil,2);
  _wsprintf(str,lpFmt,lpVars);
  NowToStr(strtime);
  CRLF[0]:=#13;CRLF[1]:=#10;CRLF[2]:=#0;
  _wsprintf(buf,'%s->%s%s',[strtime,str,CRLF]);
  Len:=lstrlen(buf);
  writefile(hFile,buf,Len,NumOfWritten,nil);
  closehandle(hFile);
end;

procedure Log(str:PChar;Data:pointer;dwSize:DWORD);
var
  hFile,NumOfWritten:cardinal;
  Len:integer;
  CRLF:array[0..2] of char;
  buf:array[0..1023] of char;
  strtime:array[0..127] of char;
begin
  if not test then exit;
  createdirectory(LOG_DIR,nil);
  hFile:=createfile(LOG_FILE,GENERIC_WRITE,FILE_SHARE_READ,nil,
                     OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
  if hFile=INVALID_HANDLE_VALUE then exit;
  setfilepointer(hFile,0,nil,2);

  NowToStr(strtime);
  CRLF[0]:=#13;CRLF[1]:=#10;CRLF[2]:=#0;
  _wsprintf(buf,'%s->%s数据块（大小：%d）%s',[strtime,str,dwSize,CRLF]);
  Len:=lstrlen(buf);
  writefile(hFile,buf,Len,NumOfWritten,nil);
  writefile(hFile,Data,dwSize,NumOfWritten,nil);
  closehandle(hFile);
end;

function GetAPIErr(str:PChar):PChar;
begin
  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS, //FORMAT_MESSAGE_ARGUMENT_ARRAY
      nil,GetLastError,0,str,256,nil); //MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
  result:=str;
end;

procedure GetAPIErr();
var
    ErrMsg:Array[0..255] of char;
    errCode:cardinal;
begin
  if not test then exit;
  errCode:=GetLastError;
  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS, //FORMAT_MESSAGE_ARGUMENT_ARRAY
      nil,errCode,0,ErrMsg,sizeof(ErrMsg),nil); //MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
  Log('%s',[ErrMsg]);
end;

function _wsprintf(lpOut: PChar; lpFmt: PChar; lpVars: Array of Const):Integer; assembler;
var
  Count:integer;
  v1,v2:integer;
asm
  mov v1,eax
  mov v2,edx
  mov eax,ecx
  mov ecx,[ebp+$08]
  inc ecx
  mov Count,ecx
  dec ecx
  imul ecx,8
  add eax,ecx
  mov ecx,Count
  @@1:
  mov edx,[eax]
  push edx
  sub eax,8
  loop @@1
  push v2
  push v1
  Call wsprintf
  mov ecx,Count
  imul ecx,4
  add ecx,8
  add esp,ecx
end;

function NowToStr(Str:pchar):Pchar;
var
  St: TSystemTime;
begin
  GetLocalTime(st);
  _wsprintf(str,'%04d年%02d月%02d日%02d点%02d分%03d秒',[st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond]);
  result:=str;
end;
begin
  EnableTest();
end.

