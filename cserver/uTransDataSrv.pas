unit uTransDataSrv;

interface
uses winsock,windows,funcs,zip,func,graphics,classes,uDebug;
const
  wm_user=$0400;
  wm_TransData=wm_user+100+1;
  MAXBUF=8192;
  MAXPATH=260;
  PORT=7622;
  PORT2=7623;
type
  TThreadType=(FTransFile,FTransScr,FGetRet,FTypeClient,FListenSocket,FMainThread,FTransfer,FTransferMain,FRecvData);
  Torder=(FStart,Fclose);
  TAPIFlag=(FWSAStartup,Fsocket,Fsetsockopt,Fbind,Flisten,Faccept,Frecv,FcreateFile,FGetFileSize,Fsend,FRecv2,
            FWriteFile,FSetFilePointer,Frecv_S,FSetFilePointer_S,FReadFile_S,FReadFile_S1,Fsend_S,Fcreatethread,
            FGetFileAttributes,FDirectoryCompression,FDirectoryCompression_1,FDirectoryDecompression_1,FDirectoryDecompression,
            Fdeletefile,FRecv3,FCreateDIBSection,FNull,FthreadStart,FthreadEnd,Fverify);
  TAPIType=(Fwindows,Fsock);
  TScrOrder=(FScrStart,FScrPause,FScrContinue,FScrClose);
  TRequestType=(RTransFile,RTransScr,RRecvData);
  pSocket=^stSocket;
  stSocket=packed record
    socketHandle:tsocket;
    addr:tsockaddr;
    addrLen:integer;
  end;
  pRunAPIInfo=^stRunAPIInfo;
  stRunAPIInfo=packed record
    aAPI:TAPIFlag;
    APIType:TAPIType;
    result:integer;
    errCode:integer;
    Info:array[0..1023] of ansiChar;
  end;
  pTransRate=^stTransRate;
  stTransRate=packed record
    Transed:cardinal;
    TransedHigh:cardinal;
    Speed:int64;
  end;
  pFileInfo=^stFileInfo;
  stFileInfo=packed record
    hFile:cardinal;
    isUpLoad:bool;
    FileName:array[0..MAXPATH-1] of ansiChar;
    FileSize:cardinal;
    FileSizeHigh:cardinal;
    ClientFileSize:cardinal;
    ClientFileSizeHigh:cardinal;
  end;
  pSendMsgTo=^stSendMsgTo;
  stSendMsgTo=packed record
    hform:hwnd;
    msgType:cardinal;
  end;
  pThreadInfo=^stThreadInfo;
  stThreadInfo=packed record
    threadType:TThreadType;
    active:bool;
    hThread:cardinal;
    threadID:cardinal;
  end;
  pMainTread=^stMainTread;
  stMainTread=packed record
    threadType:TThreadType;
    order:Torder;
  end;
  pListenSocket=^stListenSocket;
  stListenSocket=packed record
    thread:stThreadInfo;
    runAPI:stRunAPIInfo;
    sendMsg:stSendMsgTo;
    socket:stSocket;
    wsadata: TWSAData;
  end;
  pTypeCS=^stTypeCS;
  stTypeCS=packed record
    thread:stThreadInfo;
    runAPI:stRunAPIInfo;
    sendMsg:stSendMsgTo;
    socket:stSocket;
    TransType:TThreadType;
    oh:stOrdHeader;
  end;
  pTransFilesCS=^stTransFilesCS;
  stTransFilesCS=packed record
    thread:stThreadInfo;
    runAPI:stRunAPIInfo;
    sendMsg:stSendMsgTo;
    socket:stSocket;
    fileInfo:stFileInfo;
    transRate:stTransRate;
  end;
  pTransScrCS=^stTransScrCS;
  stTransScrCS=packed record
    thread:stThreadInfo;
    runAPI:stRunAPIInfo;
    sendMsg:stSendMsgTo;
    socket:stSocket;
    hBmp:HBITMAP;
    stream:tmemoryStream;
    order:TScrOrder;
    transRate:stTransRate;
  end;
  pGetRetCS=^stGetRetCS;
  stGetRetCS=packed record
    thread:stThreadInfo;
    runAPI:stRunAPIInfo;
    sendMsg:stSendMsgTo;
    socket:stSocket;
    lpszBuf:pointer;
    transRate:stTransRate;
  end;
  pSvrAddr=^stSvrAddr;
  stSvrAddr=packed record
    port:Word;
    case flg:byte of
    0:(IP:array[0..15] of ansiChar);
    1:(DN:array[0..30] of ansiChar);
  end;
  stRequestFileInfo=packed record
    fileName:array[0..MAXPATH-1] of ansiChar;
    bUpLoad:bool;
  end;//
  pTransFilesInfo=^stTransFilesInfo;
  stTransFilesInfo=packed record
    server:stSvrAddr;
    clientFile:array[0..MAX_PATH-1] of ansiChar;
    serverFile:array[0..MAX_PATH-1] of ansiChar;
    bUpLoad:bool;
    bFolder:bool;
    bCompleteDel:bool;
  end;

  pTransferCS=^stTransferCS;
  stTransferCS=packed record
    thread:stThreadInfo;
    runAPI:stRunAPIInfo;
    sendMsg:stSendMsgTo;
    RecvSocket,SendSocket:stSocket;
    buf:array[0..1023] of ansiChar;
    transRate:stTransRate;
  end;

  pRecvDataCS=^stRecvDataCS;
  stRecvDataCS=packed record
    thread:stThreadInfo;
    runAPI:stRunAPIInfo;
    sendMsg:stSendMsgTo;
    socket:stSocket;
    oh:stOrdHeader;
    transRate:stTransRate;
  end;

procedure TransDataThread(pLisenSocketInfo:pointer);stdcall;
//function RunAPIOK(pThreadDataInfo:pointer):bool;stdcall;
procedure GetAPIErrCode(pRun:pRunAPIInfo);stdcall;
procedure TransTypeThread(pClientSocketInfo:pointer);stdcall;
procedure TransDirThread(pTransFilesInfo:pointer);stdcall;
function TransDirAPI(pTransFilesInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
procedure TransFileThread(pTransFileInfo:pointer);stdcall;
function TransFileAPI(pTransFileInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
procedure TransScrThread(pTransScrInfo:pointer);stdcall;
function TransScrAPI(pTransScrInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
function TransTypeAPI(pTransTypeInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
function TransDataAPI(pLisenSocketInfo:pointer;FAPI:TAPIFlag):bool;stdcall;
//procedure GetRetThread();stdcall;
procedure GetScrThread(pTransScrInfo:pointer);stdcall;
function GetScrAPI(pTransScrInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
procedure ResumeStream(FirstStream,SecondStream:TMemorystream);
function TransferAPI(pLisenSocketInfo:pointer;FAPI:TAPIFlag):bool;stdcall;
procedure TransferThread(pLisenSocketInfo:pointer);stdcall;
procedure TransferClient(pTransferPara:pointer);stdcall;
function TransferClientAPI(pTransferPara:pointer;FAPI:tAPIFlag):bool;stdcall;
procedure RecvDataThread(pRecvInfo:pointer);stdcall;
function RecvDataAPI(pRcvDataInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
implementation
procedure RecvDataThread(pRecvInfo:pointer);stdcall;

var
  pData:pRecvDataCS;
  NumberOfRead:cardinal;
  p:pointer;
begin
  pData:=pRecvInfo;
  RecvDataAPI(pData,FthreadStart);
  if pData^.oh.DataSize<=0 then exit;
  GetMem(pData^.oh.Data,pData^.oh.DataSize);
  pData^.transRate.Speed:=0;
  NumberOfRead:=pData^.oh.DataSize;
  ZeroMemory(pData^.oh.Data,pData^.oh.DataSize);
  //uDebug.Log('data size:%d',[NumberOfRead]);//test
  p:=pData^.oh.Data;
  while NumberOfRead>0 do
  begin
    pData^.runAPI.result:=Recv(pData^.socket.socketHandle,p^,NumberOfRead,0);
    //uDebug.Log('data size:%d',[pData^.runAPI.result]);  //test
    if not RecvDataAPI(pData,FRecv) then break;
    p:=pointer(dword(p)+dword(pData^.runAPI.result));
    pData^.transRate.Transed:=pData^.transRate.Transed+pData^.runAPI.result;
    pData^.transRate.Speed:=pData^.transRate.Speed+pData^.runAPI.result;
    NumberOfRead:=NumberOfRead-pData^.runAPI.result;
  end;//while
  //uDebug.Log('my:',pData^.oh.Data,pData^.oh.datasize);//test
  RecvDataAPI(pData,FthreadEnd);
  //sendMessage(pData^.sendMsg.hform,pData^.sendMsg.msgType,0,integer(pData));
end;
function RecvDataAPI(pRcvDataInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
label 1;
var
  pData:pRecvDataCS;
  pRun:pRunAPIInfo;
  pThreadDataInfo:pThreadInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
begin
  result:=true;
  pThreadDataInfo:=pRcvDataInfo;
  pData:=pRcvDataInfo;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pRun^.aAPI:=FAPI;
  case pData^.runAPI.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'数据接收线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FRecv:
    begin
      pData^.runAPI.APIType:=Fsock;
      if (pData^.runAPI.result<>SOCKET_ERROR)  then exit; //
      if  pData^.runAPI.result=SOCKET_ERROR then
        strcopy(pData^.runAPI.Info,'接收数据大小失败!错误代码是：');
      if  pData^.runAPI.result=0 then
        strcopy(pData^.runAPI.Info,'接收数据大小失败!Recv返回0!可能的错误是：');
    end;//FRecv
  FthreadEnd:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'接收数据线程结束!');
      SendMessage(pMsg^.hform,pMsg^.msgType,1,integer(pData));
      goto 1;
    end;
  end;//case
  GetAPIErrCode(pRun);
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  result:=false;
1:
  closesocket(pSock^.socketHandle);
  pThreadDataInfo^.active:=false;
  if (pData^.oh.Data<>nil) then freemem(pData^.oh.Data);
  dispose(pData);
end;

procedure TransferClient(pTransferPara:pointer);stdcall;
var
  pData:pTransferCS;
begin
  pData:=pTransferPara;
  TransferClientAPI(pData,FthreadStart);
  while true do
  begin
    pData^.runAPI.result:=recv(pData^.Recvsocket.socketHandle,pData^.buf,sizeof(pData^.buf),0);
    if not TransferClientAPI(pdata,FRecv) then
    begin
      if pData^.Sendsocket.socketHandle<>0 then
      begin
        closesocket(pData^.Sendsocket.socketHandle);
        pData^.Sendsocket.socketHandle:=0;
      end;//if pData^.Sendsocket.socketHandle<>0 then
      exit;
    end;//if not TransferClientAPI(pdata,FRecv) then
    while pData^.Sendsocket.socketHandle=0 do sleep(1000);
    pData^.runAPI.result:=send(pData^.Sendsocket.socketHandle,pData^.buf,pData^.runAPI.result,0);
    if not TransferClientAPI(pData,Fsend) then
    begin
      if pData^.Sendsocket.socketHandle<>0 then
      begin
        closesocket(pData^.Sendsocket.socketHandle);
        pData^.Sendsocket.socketHandle:=0;
      end;// if pData^.Sendsocket.socketHandle<>0 then
    end;// if not TransferClientAPI(pData,Fsend) then
  end;//while
end;
function TransferClientAPI(pTransferPara:pointer;FAPI:tAPIFlag):bool;stdcall;
var
  pData:pTransferCS;
  pRun:pRunAPIInfo;
  pThreadDataInfo:pThreadInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
begin
  result:=true;
  pThreadDataInfo:=pTransferPara;
  pData:=pTransferPara;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pRun^.aAPI:=FAPI;
  case pData^.runAPI.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'数据转发线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FRecv:
    begin
      pData^.runAPI.APIType:=Fsock;
      if (pData^.runAPI.result<>SOCKET_ERROR) and (pData^.runAPI.result<>0) then exit; //
      if  pData^.runAPI.result=SOCKET_ERROR then
        strcopy(pData^.runAPI.Info,'接收数据大小失败!错误代码是：');
      if  pData^.runAPI.result=0 then
        strcopy(pData^.runAPI.Info,'接收数据大小失败!Recv返回0!可能的错误是：');
    end;//FRecv
  Fsend:
    begin
      pRun^.APIType:=Fsock;
      if (pRun^.result<>SOCKET_ERROR) and (pData^.runAPI.result<>0) then exit;
      if pRun^.result=SOCKET_ERROR then
        strcopy(pRun^.Info,'发送数据失败(SOCKET_ERROR)!');
      if pRun^.result=0 then
        strcopy(pRun^.Info,'发送数据失败(0)!');
    end;//Fsend
  end;//case
  GetAPIErrCode(pRun);
  if strlen(pData^.runAPI.Info)>0 then
    strcat(pData^.runAPI.Info,'转发线程结束！')
  else
    strcopy(pData^.runAPI.Info,'转发线程结束！');
  if pSock^.socketHandle<>0 then
  begin
    closesocket(pSock^.socketHandle);
    pSock^.socketHandle:=0;
  end;
  pThreadDataInfo^.active:=false;
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  dispose(pData);
  result:=false;
end;
procedure TransferThread(pLisenSocketInfo:pointer);stdcall;
var
  flag:bool;
  pData:pListenSocket;
  pClient,pTempClient:pTransferCS;
begin
  pTempClient:=nil;
  with pData^.runAPI,pData^.socket do
  begin
    pData:=pLisenSocketInfo;
    TransferAPI(pData,FthreadStart);
    pData^.runAPI.result:=WSAStartup($0202,pData^.wsadata);
    if not TransferAPI(pData,FWSAStartup) then exit;

    pData^.runAPI.result:=socket(AF_INET, SOCK_STREAM, 0); //SOCK_DGRAM
    if not TransferAPI(pData,Fsocket) then exit;
    pData^.socket.socketHandle:=pData^.runAPI.result;

    pData^.runAPI.result:=setsockopt(pData^.socket.socketHandle,SOL_SOCKET,SO_REUSEADDR,@flag,sizeof(flag));
    if not TransferAPI(pData,Fsetsockopt) then exit;

    zeromemory(@(pData^.socket.addr),sizeof(pData^.socket.addr));
    pData^.socket.addr.sin_family:=AF_INET;
    pData^.socket.addr.sin_port:=htons(PORT2);
    pData^.socket.addr.sin_addr.s_addr:=htonl(INADDR_ANY);

    pData^.runAPI.result:=bind(pData^.socket.socketHandle,pData^.socket.addr,sizeof(pData^.socket.addr));
    if not TransferAPI(pData,Fbind) then exit;
    pData^.runAPI.result:=listen(pData^.socket.socketHandle,5);
    if not TransferAPI(pData,Flisten) then exit;
  end;//with
  while true do
  begin
    new(pClient);
    zeromemory(pClient,sizeof(pClient^));
    pClient^.thread.active:=true;
    pClient^.thread.threadType:=FTransfer;
    pClient^.sendMsg.hform:=pData^.sendMsg.hform;
    pClient^.sendMsg.msgType:=pData^.sendMsg.msgType;

    pClient^.RecvSocket.AddrLen:=sizeof(pClient^.RecvSocket.addr);
    pClient^.SendSocket.AddrLen:=sizeof(pClient^.SendSocket.addr);

    //pClient^.socket.socketHandle:=Accept(pData^.socket.socketHandle,@(pClient^.socket.Addr),@(pClient^.socket.AddrLen));
    pData^.runAPI.result:=Accept(pData^.socket.socketHandle,@(pClient^.RecvSocket.Addr),@(pClient^.RecvSocket.AddrLen));
    if not TransferAPI(pData,Faccept) then
    begin
      dispose(pClient);
      if pData^.runAPI.errCode=WSAENOTSOCK then
      begin
        pData^.thread.active:=false;
        closesocket(pData^.socket.socketHandle);
        WSACleanup();
        dispose(pData);
        exit;
      end
      else begin
        continue;
      end;//if
    end;
    pClient^.RecvSocket.socketHandle:=pData^.runAPI.result;
    if pTempClient<>nil then
    begin
      pClient^.SendSocket:=pTempClient^.RecvSocket;
      pTempClient^.SendSocket:=pClient^.RecvSocket;
    end;
    pData^.runAPI.result:=createthread(nil,0,@TransferClient,pClient,0,pClient^.thread.threadID);
    if not TransferAPI(pData,Fcreatethread) then
    begin
      dispose(pClient);
      continue;
    end;
    pClient^.thread.hThread:=pData^.runAPI.result;
    pTempClient:=pClient;
  end;//while
end;
function TransferAPI(pLisenSocketInfo:pointer;FAPI:TAPIFlag):bool;stdcall;
var
  pData:pListenSocket;
  pRun:pRunAPIInfo;
  pThreadDataInfo:pThreadInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
  str:array[0..11] of ansiChar;
begin
  result:=true;
  pThreadDataInfo:=pLisenSocketInfo;
  pData:=pLisenSocketInfo;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pRun^.aAPI:=FAPI;
  case pRun^.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'数据转发主线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FWSAStartup:
    begin
      pRun^.APIType:=Fsock;
      if  pRun^.result=0 then exit;
      strcopy(pRun^.Info,'初始化WS2_32.DLL失败!错误代码是：');
    end;//FWSAStartup
  Fsocket:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>INVALID_SOCKET then
      begin
        strcopy(pRun^.Info,'创建侦听socket!');
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'创建socket失败!!错误代码是：');
    end;//Fsocket
  Fsetsockopt:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'setsockopt失败!错误代码是：');
    end;//Fsetsockopt
  Fbind:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'绑定socket失败!错误代码是：');
    end;//Fbind
  Flisten:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then
      begin
        strcopy(pRun^.Info,'数据转发服务处于等待中...');
        inttostr(PORT2,str);
        strcat(pRun^.Info,'(端口：');strcat(pRun^.Info,str);strcat(pRun^.Info,')');
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'侦听端口失败!错误代码是：');
    end;//Flisten
  Faccept:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>INVALID_SOCKET then exit;
      strcopy(pRun^.Info,'接受连接失败!错误代码是：');
      GetAPIErrCode(pRun);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;//Faccept
  FcreateThread:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>0 then exit;
      strcopy(pRun^.Info,'创建线程失败!错误代码是：');
      GetAPIErrCode(pRun);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;//
  end;//case
  GetAPIErrCode(pRun);
  pThreadDataInfo^.active:=false;
  closesocket(pSock^.socketHandle);
  WSACleanup();
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  dispose(pData);
  result:=false;
end;
procedure ResumeStream(FirstStream,SecondStream:TMemorystream);
//06-07-08:try
var
  I: Integer;
  P1, P2: ^ansiChar;
begin
//MyFirstStream.Position:=0;MySecondStream.Position:=0;MyCompareStream.Position:=0; //必须
//---------------------------------------------
  P1 := FirstStream.Memory;
  //MySecondStream.SetSize(MyFirstStream.Size);
  P2 := SecondStream.Memory;

  if FirstStream.Size=0 then exit;
  try
  for I := 0 to FirstStream.Size - 1 do
  begin
    if p1^='0' then p1^:=p2^;
    inc(p1);inc(p2);
  end;
  except
  end;
//---------------------------------------------
  secondStream.Clear;
  firstStream.Position:=0;
  secondStream.CopyFrom(firstStream,firstStream.Size);
  FirstStream.Clear;
  SecondStream.Position:=0;//必须,否则永远只显示第一幅图像
end;
function GetScrAPI(pTransScrInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
var
  pData:pTransScrCS;
  pRun:pRunAPIInfo;
  pThreadDataInfo:pThreadInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
begin
  result:=true;
  pThreadDataInfo:=pTransScrInfo;
  pData:=pTransScrInfo;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pRun^.aAPI:=FAPI;
  case pData^.runAPI.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'图像传输线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FRecv:
    begin
      pData^.runAPI.APIType:=Fsock;
      if (pData^.runAPI.result<>SOCKET_ERROR) and (pData^.runAPI.result<>0) then exit; //
      if  pData^.runAPI.result=SOCKET_ERROR then
        strcopy(pData^.runAPI.Info,'接收数据大小失败!错误代码是：');
      if  pData^.runAPI.result=0 then
        strcopy(pData^.runAPI.Info,'接收数据大小失败!Recv返回0!可能的错误是：');
    end;//FRecv
  Fsend:
    begin
      pRun^.APIType:=Fsock;
      if (pRun^.result<>SOCKET_ERROR) and (pData^.runAPI.result<>0) then exit;
      if pRun^.result=SOCKET_ERROR then
        strcopy(pRun^.Info,'发送Ready数据失败(SOCKET_ERROR)!');
      if pRun^.result=0 then
        strcopy(pRun^.Info,'发送Ready数据失败(0)!');
    end;//Fsend
  FRecv2:
    begin
      pRun^.APIType:=Fsock;
      if (pData^.runAPI.result<>INVALID_SOCKET) and (pData^.runAPI.result<>0) then exit; //
      if  pData^.runAPI.result=INVALID_SOCKET then
        strcopy(pData^.runAPI.Info,'接收数据失败!错误代码是：');
      if  pData^.runAPI.result=0 then
        strcopy(pData^.runAPI.Info,'接收数据失败!Recv返回0!可能的错误是：');
    end;
  FthreadEnd:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'图像传输线程结束!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
    end;
  end;//case
  GetAPIErrCode(pRun);
  closesocket(pSock^.socketHandle);
  pThreadDataInfo^.active:=false;
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  pData^.stream.Free;
  dispose(pData);
  result:=false;
end;
procedure GetScrThread(pTransScrInfo:pointer);stdcall;
//06-07-08 try
label 1;
var
  bFirst:bool;
  pData:pTransScrCS;
  size,i:integer;
  buf:array[0..maxbuf-1] of ansiChar;
  firstStream:tmemorystream;
  p:pointer;
  //bmp:tbitmap;
begin
  pData:=pTransScrInfo;
  GetScrAPI(pData,FthreadStart);
  firstStream:=tmemorystream.Create;
  //bmp:=tbitmap.Create;
  pData^.stream:=tmemorystream.Create;
  bFirst:=true;
  while  true do
  begin
    while pData^.order=FScrPause do sleep(1000);
    if pData^.order=FScrClose then
    begin //1.发送控制命令
      pData^.runAPI.result:=send(pData^.socket.socketHandle,pData^.order,sizeof(pData^.order),0);
      GetScrAPI(pData,FthreadEnd);
      goto 1;
    end;
    pData^.runAPI.result:=send(pData^.socket.socketHandle,pData^.order,sizeof(pData^.order),0);
    if not GetScrAPI(pData,Fsend) then goto 1; //1.发送控制命令
    pData^.transRate.Transed:=0;
    pData^.transRate.Speed:=0;
    pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.transRate.TransedHigh,sizeof(pData^.transRate.TransedHigh),0);
    if not GetScrAPI(pdata,FRecv) then goto 1; //2.接收数据大小
    firstStream.SetSize(pData^.transRate.TransedHigh);
    p:=firstStream.Memory;  //3.接收数据
    while  pData^.transRate.Transed<pData^.transRate.TransedHigh do
    begin
      i:=pData^.transRate.TransedHigh-pData^.transRate.Transed;
      try
      pData^.runAPI.result:=Recv(pData^.socket.socketHandle,p^,i,0);
      except
      pData^.runAPI.result:=-1;
      end;
      if not GetScrAPI(pData,FRecv2) then goto 1;
      p:=pointer(cardinal(p)+cardinal(pData^.runAPI.result));
      pData^.transRate.Transed:=pData^.transRate.Transed+cardinal(pData^.runAPI.result);
      pData^.transRate.Speed:=pData^.transRate.Speed+pData^.runAPI.result;
      sleep(0);
    end;//while
    if bFirst then
    begin
      bFirst:=false;
      DecompressStream(firstStream,pData^.stream);
    end
    else begin
      DecompressStream(firstStream);
      ResumeStream(firstStream,pData^.stream);
    end;//if not first
    //bmp.LoadFromStream(pData^.stream);
    //pData^.hBmp:=bmp.Handle;
    if (pData^.stream.Size=230454)or(pData^.stream.Size=1440054) then
    sendMessage(pData^.sendMsg.hform,pData^.sendMsg.msgType,66,integer(pData))
    else
    sendMessage(pData^.sendMsg.hform,pData^.sendMsg.msgType,88,integer(pData));
    sleep(0);
  end;//while true
1:
  firstStream.Free;
  //bmp.Free;
end;
{
procedure GetRetThread();stdcall;
var
  pData:pGetRetCS;
  dwSize:DWORD;
begin
  pData^.runAPI.result:=Recv(pData^.socket.socketHandle,dwSize,sizeof(DWORD),0);
  pData^.runAPI.aAPI:=FRecv;
  if not TransScrAPI(pData) then exit;
  pData^.transRate.Transed:=0;
  pData^.transRate.Speed:=0;
  pData^.transRate.TransedHigh:=dwSize;
  //  p:=biData;
    while  pData^.transRate.Transed<pData^.transRate.TransedHigh do
    begin
    //  i:=pData^.transRate.TransedHigh-pData^.transRate.Transed;
      pData^.runAPI.result:=Recv(pData^.socket.socketHandle,p^,i,0);
      if pData^.runAPI.result=0 then break;
      pData^.runAPI.aAPI:=FRecv2;
      pData^.runAPI.APIType:=Fsock;
      if not TransScrAPI(pData) then exit;
      p:=pointer(cardinal(p)+cardinal(pData^.runAPI.result));
      pData^.transRate.Transed:=pData^.transRate.Transed+cardinal(pData^.runAPI.result);
      pData^.transRate.Speed:=pData^.transRate.Speed+pData^.runAPI.result;
      sleep(0);
    end;//while
end;
}

function TransScrAPI(pTransScrInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
var
  pData:pTransScrCS;
  pRun:pRunAPIInfo;
  pThreadDataInfo:pThreadInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
begin
  result:=true;
  pThreadDataInfo:=pTransScrInfo;
  pData:=pTransScrInfo;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pRun^.aAPI:=FAPI;
  case pData^.runAPI.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'图像传输线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FRecv:
    begin
      pRun^.APIType:=Fsock;
      if (pData^.runAPI.result<>INVALID_SOCKET) and (pData^.runAPI.result<>0) then exit; //
      if  pData^.runAPI.result=INVALID_SOCKET then
        strcopy(pData^.runAPI.Info,'接收BI数据失败!错误代码是：');
      if  pData^.runAPI.result=0 then
        strcopy(pData^.runAPI.Info,'接收BI数据失败!Recv返回0!可能的错误是：');
    end;
  Fsend:
    begin
      pRun^.APIType:=Fsock;
      if (pRun^.result<>SOCKET_ERROR) and (pData^.runAPI.result<>0) then exit;
      if pRun^.result=SOCKET_ERROR then
        strcopy(pRun^.Info,'发送Ready数据失败(SOCKET_ERROR)!');
      if pRun^.result=0 then
        strcopy(pRun^.Info,'发送Ready数据失败(0)!');
    end;//Fsend
  FRecv2:
    begin
      pRun^.APIType:=Fsock;
      if (pData^.runAPI.result<>INVALID_SOCKET) and (pData^.runAPI.result<>0) then exit; //
      if  pData^.runAPI.result=INVALID_SOCKET then
        strcopy(pData^.runAPI.Info,'接收第一屏数据失败!错误代码是：');
      if  pData^.runAPI.result=0 then
        strcopy(pData^.runAPI.Info,'接收第一屏数据失败!Recv返回0!可能的错误是：');
    end;
  FRecv3:
    begin
      pRun^.APIType:=Fsock;
      if (pData^.runAPI.result<>INVALID_SOCKET) and (pData^.runAPI.result<>0) then exit; //
      if  pData^.runAPI.result=INVALID_SOCKET then
        strcopy(pData^.runAPI.Info,'接收变化数据失败!错误代码是：');
      if  pData^.runAPI.result=0 then
        strcopy(pData^.runAPI.Info,'接收变化数据失败!Recv返回0!可能的错误是：');
    end;
  FCreateDIBSection:
    begin
      pRun^.APIType:=Fwindows;
      exit;
    end;//FCreateDIBSection
  end;//case
  GetAPIErrCode(pRun);
  closesocket(pSock^.socketHandle);
  pThreadDataInfo^.active:=false;
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  dispose(pData);
  result:=false;
end;
procedure TransScrThread(pTransScrInfo:pointer);stdcall;
type
  stChange=packed record
    pointer:cardinal;
    data:cardinal;
  end;
var
  pData:pTransScrCS;

  bi:BITMAPINFO;
  biBitCount:word;
  biData,p:pointer;
  biWidth,biHeight:integer;
  Ready:byte;
  isFirst,isFlash:bool;

  recvChange:array[0..1023] of stChange;
  i,j:cardinal;

  dwpalettesize:DWORD;
  hPal:HPALETTE;
  hMemDC:hdc;
  palBuf:array[0..4+256*sizeof(PALETTEENTRY)] of ansiChar;
  ppe:PLOGPALETTE;  
begin
  isFirst:=true;
  pData:=pTransScrInfo;
  TransScrAPI(pData,FthreadStart);
  ZeroMemory(@bi,40);
  pData^.runAPI.result:=Recv(pData^.socket.socketHandle,bi,40,0);
  if not TransScrAPI(pData,FRecv) then exit;
  biBitCount:=bi.bmiHeader.biBitCount;
  biWidth:=bi.bmiHeader.biWidth;
  biHeight:=bi.bmiHeader.biHeight;
  if biBitCount>=24 then
    pData^.hBmp := CreateDIBSection(getDC(0), bi,
        DIB_RGB_COLORS,biData,0, 0)
  else
    pData^.hBmp := CreateDIBSection(getDC(0), bi,
        DIB_PAL_COLORS,biData,0, 0);
  if not TransScrAPI(pData,FCreateDIBSection) then exit;
  //pData^.transRate.TransedHigh:=((biWidth* biBitCount+31) div 8)*biHeight;
  pData^.transRate.TransedHigh:=biWidth* biBitCount*biHeight div 8;

  hMemDC := CreateCompatibleDC(getDC(0)) ;
  SelectObject(hMemDC,pData^.hBmp);
  ppe:=@palBuf[0];
  ppe^.palNumEntries:=1 shl biBitCount;
  GetSystemPaletteEntries(getDC(0), 0, ppe^.palNumEntries, ppe^.palPalEntry);
  ppe^.palVersion := $300;
  hPal := CreatePalette(ppe^);
  SelectPalette(hMemDC, hPal, FALSE);
  DeleteDC(hMemDC);


  Ready:=88;
  while  true do
  begin
    pData^.runAPI.result:=send(pData^.socket.socketHandle,Ready,sizeof(Ready),0);
    if not TransScrAPI(pData,Fsend) then exit;
    if isFirst then
    begin
    pData^.transRate.Transed:=0;
    pData^.transRate.Speed:=0;
    p:=biData;
    while  pData^.transRate.Transed<pData^.transRate.TransedHigh do
    begin
      i:=pData^.transRate.TransedHigh-pData^.transRate.Transed;
      pData^.runAPI.result:=Recv(pData^.socket.socketHandle,p^,i,0);
      if pData^.runAPI.result=0 then break;
      if not TransScrAPI(pData,FRecv2) then exit;
      p:=pointer(cardinal(p)+cardinal(pData^.runAPI.result));
      pData^.transRate.Transed:=pData^.transRate.Transed+cardinal(pData^.runAPI.result);
      pData^.transRate.Speed:=pData^.transRate.Speed+pData^.runAPI.result;
      sleep(0);
    end;//while
    isFirst:=false;
    isFlash:=true;
    end //nor ia first
    else begin
      pData^.transRate.Transed:=0;
      pData^.transRate.Speed:=0;
      isFlash:=false;
      while true do
      begin
        p:=@recvChange[0];
        i:=MAXBUF;
        while i>0 do
        begin
          pData^.runAPI.result:=Recv(pData^.socket.socketHandle,p^,i,0);
          if not TransScrAPI(pData,FRecv3) then exit;
          pData^.transRate.Transed:=pData^.transRate.Transed+pData^.runAPI.result;
          pData^.transRate.Speed:=pData^.transRate.Speed+pData^.runAPI.result;
          i:=i-pData^.runAPI.result;
          p:=pointer(cardinal(p)+pData^.runAPI.result);
        end;// while i<MAXBUF do
        for i:=0 to 1023 do
        begin
          j:=i;
          if (recvChange[i].pointer=$FFFFFFFF) and (recvChange[i].data=$FFFFFFFF) then break;
          pcardinal(cardinal(biData)+recvChange[i].pointer)^:=recvChange[i].data;
        end;
        if (recvChange[j].pointer=$FFFFFFFF) and (recvChange[j].data=$FFFFFFFF) then break;
        isFlash:=true;
        //sleep(100);
      end;//while true do
    end;//is not first ]
    if isFlash then
      sendMessage(pData^.sendMsg.hform,pData^.sendMsg.msgType,88,integer(pData));
  end;//while true
end;//
function TransDirAPI(pTransFilesInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
var
  pdata:pTransFilesCS;
  pRun:pRunAPIInfo;
  pThreadDataInfo:pThreadInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
  pFile:pFileInfo;
begin
  result:=true;
  pdata:=pTransFilesInfo;
  pThreadDataInfo:=pTransFilesInfo;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pFile:=pFileInfo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo)+sizeof(stSocket));
  pRun^.aAPI:=FAPI;
  case pRun^.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'文件传输线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  Frecv:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'接收数据失败!错误代码是：');
    end;//Frecv
  FDirectoryCompression_1:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'开始压缩文件..!');
      strcat(pRun^.Info,pFile^.fileName);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FDirectoryCompression:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result>0 then
      begin
        strcopy(pRun^.Info,'压缩文件完成!');
        strcat(pRun^.Info,pFile^.fileName);
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end
      else begin
        strcopy(pRun^.Info,'压缩文件失败!');
        strcat(pRun^.Info,pFile^.fileName);
      end;
    end;//FDirectoryCompression
    FcreateFile:
      begin
        pRun^.APIType:=Fwindows;
        if (pRun^.result<>-1) then exit;
        strcopy(pRun^.Info,'创建文件失败!错误代码是：');
      end;//FcreateFile:
  FGetFileSize:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>-1 then exit;
      if (pRun^.result=-1) and (GetLastError()=NO_ERROR) then exit;
      strcopy(pRun^.Info,'获取文件大小失败!');
    end;//FGetFileSize
  FSetFilePointer:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'设置文件位置失败!!');
    end;//FSetFilePointer
  Fsend:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'发送数据失败!');
    end;//Fsend
  Frecv2:
    begin
      pRun^.APIType:=Fsock;
      if (pRun^.result<>INVALID_SOCKET) and (pRun^.result<>0) then exit;
      if pRun^.result=SOCKET_ERROR then
      begin
        strcopy(pRun^.Info,'接收文件数据失败!');
        GetAPIErrCode(pRun);
      end;
      if pRun^.result=0 then
        strcopy(pRun^.Info,'文件接收完成!');
        strcat(pRun^.Info,pFile^.FileName);
    end; //Frecv2
  FWriteFile:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'写文件失败!');
    end;//Fwritefile
  Frecv_S:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result=4 then exit;
      strcopy(pRun^.Info,'接收文件大小失败!(发送文件)');
    end;//Frecv_S
  FSetFilePointer_S:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'设置文件位置失败!(发送文件)');
    end;//FSetFilePointer_S
  FReadFile_S:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'读文件失败!(发送文件)');
    end;//Freadfile_s
  FReadFile_S1:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result>0 then exit;
      strcopy(pRun^.Info,'发送文件完成!(发送文件)');
      strcat(pRun^.Info,pFile^.fileName);
    end;//Freadfile_s1
  Fsend_S:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'发送数据失败!(发送文件)');
    end;
  FGetFileAttributes:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'获取文件属性失败!');
    end;
  FDirectoryDecompression_1:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'开始解压缩文件..!');
      strcat(pRun^.Info,pFile^.fileName);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FDirectoryDecompression:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result>0 then
      begin
        strcopy(pRun^.Info,'解压缩文件完成!');
        strcat(pRun^.Info,pFile^.fileName);
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'解压缩文件失败!');
      strcat(pRun^.Info,pFile^.fileName);
    end;//
    Fdeletefile:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'删除文件失败!');
      strcat(pRun^.Info,pFile^.fileName);
    end;
  end;//case
  GetAPIErrCode(pRun);
  closesocket(pSock^.socketHandle);
  CloseHandle(pFile^.hFile);
  pThreadDataInfo^.active:=false;
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  dispose(pData);
  result:=false;
end;
procedure TransDirThread(pTransFilesInfo:pointer);stdcall;
//06-06-06
var
  pdata:pTransFilesCS;
  buf:array[0..MAXBUF-1] of ansiChar;
  RequestFileInfo:stRequestFileInfo;
  wLen,NumberOfRead:cardinal;
  ZipFileName:array[0..MAXPATH] of ansiChar;
  Dir:array[0..MAXPATH] of ansiChar;
  //fileSize,wLen,clientFileSize,NumberOfRead,fileSizehigh,clientFileSizeHigh:cardinal;
  //RecvLen:integer;
begin
  pdata:=pTransFilesInfo;
  TransDirAPI(pData,FthreadStart);
  pData^.runAPI.result:=Recv(pData^.socket.socketHandle,RequestFileInfo,sizeof(RequestFileInfo),0);
  if not TransDirAPI(pData,Frecv) then exit;
    //worksfoldter:
  strcopy(ZipFileName,ExtractFileName(RequestFileInfo.fileName));
  if(lstrcmpiA(ZipFileName,RequestFileInfo.fileName)=0) then
  begin
    strcopy(RequestFileInfo.fileName,GetWorksFolder(Dir));
    strcat(RequestFileInfo.fileName,'\');strcat(RequestFileInfo.fileName,ZipFileName);
  end;
  
  strcopy(pData^.fileInfo.fileName,RequestFileInfo.fileName);
  pData^.fileInfo.isUpLoad:=RequestFileInfo.bupLoad;

  if not RequestFileInfo.bUpLoad then
  begin
    pData^.runAPI.result:=GetFileAttributesA(RequestFileInfo.fileName);
    if not TransDirAPI(pData,FGetFileAttributes) then exit;

    if (FILE_ATTRIBUTE_DIRECTORY and pData^.runAPI.result) <> 0 then
    begin
      strcopy(ZipFileName,RequestFileInfo.fileName);
      strcat(ZipFileName,'.dir');

      TransDirAPI(pData,FDirectoryCompression_1);
      pData^.runAPI.result:=DirectoryCompression(RequestFileInfo.fileName,ZipFileName);
      if not TransDirAPI(pData,FDirectoryCompression) then exit;
      
      strcopy(RequestFileInfo.fileName,ZipFileName);
    end;//if (FILE_ATTRIBUTE_DIRECTORY and pData^.runAPI.result) <> 0 then
    pData^.runAPI.result:=CreateFileA(RequestFileInfo.fileName,GENERIC_READ,FILE_SHARE_READ,
      nil,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_ARCHIVE,0);

    if not TransDirAPI(pData,FCreateFile) then exit;

    pData^.fileInfo.hFile:=pData^.runAPI.result;
  end//if not RequestFileInfo.isUpLoad then
  else begin
    pData^.runAPI.result:=CreateFileA(RequestFileInfo.fileName,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,
      nil,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_ARCHIVE,0);

    if not TransDirAPI(pData,FCreateFile) then exit;

    pData^.fileInfo.hFile:=pData^.runAPI.result;
  end; // 上传
  pData^.runAPI.result:=GetFileSize(pData^.fileInfo.hFile,@pData^.fileInfo.fileSizehigh);
  if not TransDirAPI(pData,FGetFileSize) then exit;

  pData^.fileInfo.FileSize:=pData^.runAPI.result;

  if RequestFileInfo.bUpLoad then
    begin
      pData^.transRate.Transed:=pData^.fileInfo.FileSize;
      pData^.transRate.TransedHigh:=pData^.fileInfo.FileSizeHigh;

      pData^.runAPI.result:=SetFilePointer(pData^.fileInfo.hFile,0,nil,FILE_END);
      if not TransDirAPI(pData,FSetFilePointer) then exit;

      pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.fileInfo.ClientFileSize,4,0);
      if not TransDirAPI(pData,Frecv) then exit;
      pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.fileInfo.ClientFileSizeHigh,4,0);
      if not TransDirAPI(pData,Frecv) then exit;

      pData^.runAPI.result:=send(pData^.socket.socketHandle,pData^.fileInfo.fileSize,4,0);
      if not TransDirAPI(pData,Fsend) then exit;
      pData^.runAPI.result:=send(pData^.socket.socketHandle,pData^.fileInfo.fileSizeHigh,4,0);
      if not TransDirAPI(pData,Fsend) then exit;
      pData^.transRate.Speed:=0;
      while true do
      begin
        FillChar(buf,SizeOf(buf),0);
        pData^.runAPI.result:=Recv(pData^.socket.socketHandle,buf,sizeof(buf),0);
        if not TransDirAPI(pData,FRecv2) then break;

        if cardinal($FFFFFFFF)-pData^.transRate.Transed<cardinal(pData^.runAPI.result) then
          pData^.transRate.TransedHigh:=pData^.transRate.TransedHigh+1;
        pData^.transRate.Transed:=pData^.transRate.Transed+DWORD(pData^.runAPI.result);
        pData^.transRate.Speed:=pData^.transRate.Speed+DWORD(pData^.runAPI.result);

        pData^.runAPI.result:=integer(WriteFile(pData^.fileInfo.hFile,Buf,pData^.runAPI.result,wLen,nil));
        if not TransDirAPI(pData,FWriteFile) then exit;
      end;//while
    end
    else begin
      pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.fileInfo.ClientFileSize,4,0);
      if not TransDirAPI(pData,Frecv_S) then exit;
      pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.fileInfo.ClientFileSizeHigh,4,0);
      if not TransDirAPI(pData,Frecv_S) then exit;

      pData^.runAPI.result:=SetFilePointer(pData^.fileInfo.hFile,pData^.fileInfo.ClientFileSize,@pData^.fileInfo.ClientFileSizeHigh,FILE_BEGIN);
      if not TransDirAPI(pData,FSetFilePointer_S) then exit;
      
      pData^.transRate.Transed:=pData^.fileInfo.ClientFileSize;
      pData^.transRate.TransedHigh:=pData^.fileInfo.ClientFileSizeHigh;
      pData^.transRate.Speed:=0;
      while true do
      begin
        pData^.runAPI.result:=integer(ReadFile(pData^.fileInfo.hFile,buf,sizeof(buf),NumberOfRead,nil));
        if not TransDirAPI(pData,FReadFile_S) then  break;
        pData^.runAPI.result:=NumberOfRead;
        if not TransDirAPI(pData,FReadFile_S1) then  break;

        pData^.runAPI.result:=send(pData^.socket.socketHandle,buf,NumberOfRead,0);
        if not TransDirAPI(pData,Fsend_S) then  exit;

        if $FFFFFFFF-pData^.transRate.Transed<pData^.runAPI.result then
          pData^.transRate.TransedHigh:=pData^.transRate.TransedHigh+1;
        pData^.transRate.Transed:=pData^.transRate.Transed+DWORD(pData^.runAPI.result);
        pData^.transRate.Speed:=pData^.transRate.Speed+DWORD(pData^.runAPI.result);
      end;//send(socket1,buf,NumberOfRead,0);
    end; //not if TransFileInfo.upLoad then

  if RequestFileInfo.bUpLoad then
  begin
    if strpos(RequestFileInfo.fileName,'.dir')<>nil then
    begin
      strlcopy(Dir,RequestFileInfo.fileName,strlen(RequestFileInfo.fileName)-4);
      createdirectoryA(Dir,nil);

      TransDirAPI(pData,FDirectoryDecompression_1);
      pData^.runAPI.result:=DirectoryDecompression(Dir,RequestFileInfo.fileName);
      if not TransDirAPI(pData,FDirectoryDecompression) then exit;
      
      pData^.runAPI.result:=integer(deletefileA(RequestFileInfo.fileName));
      if not TransDirAPI(pData,Fdeletefile) then exit;
    end;//if strpos(RequestFileInfo.fileName,'dir')<>nil then
  end//if RequestFileInfo.upLoad then
  else begin
    if strpos(RequestFileInfo.fileName,'.dir')<>nil then
    begin
      pData^.runAPI.result:=integer(deletefileA(RequestFileInfo.fileName));
      if not TransDirAPI(pData,Fdeletefile) then exit;
    end;//if strpos(RequestFileInfo.fileName,'dir')<>nil then
  end;//if RequestFileInfo.isUpLoad then
end;
function TransFileAPI(pTransFileInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
var
  pdata:pTransFilesCS;
  pRun:pRunAPIInfo;
  pThreadDataInfo:pThreadInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
  pFile:pFileInfo;
begin
  result:=true;
  pdata:=pTransFileInfo;
  pThreadDataInfo:=pTransFileInfo;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pFile:=pFileInfo(pansiChar(pSock)+sizeof(stSocket));
  pRun^.aAPI:=FAPI;
  case pRun^.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'文件传输线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  Frecv:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'接收数据失败!错误代码是：');
    end;//Frecv
  FDirectoryCompression_1:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'开始压缩文件..!');
      strcat(pRun^.Info,pFile^.fileName);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FDirectoryCompression:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result>0 then
      begin
        strcopy(pRun^.Info,'压缩文件完成!');
        strcat(pRun^.Info,pFile^.fileName);
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end
      else begin
        strcopy(pRun^.Info,'压缩文件失败!');
        strcat(pRun^.Info,pFile^.fileName);
      end;
    end;//FDirectoryCompression
    FcreateFile:
      begin
        pRun^.APIType:=Fwindows;
        if (pRun^.result<>-1) then exit;
        strcopy(pRun^.Info,'创建文件失败!错误代码是：');
      end;//FcreateFile:
  FGetFileSize:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>-1 then exit;
      if (pRun^.result=-1) and (GetLastError()=NO_ERROR) then exit;
      strcopy(pRun^.Info,'获取文件大小失败!');
    end;//FGetFileSize
  FSetFilePointer:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'设置文件位置失败!!');
    end;//FSetFilePointer
  Fsend:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'发送数据失败!');
    end;//Fsend
  Frecv2:
    begin
      pRun^.APIType:=Fsock;
      if (pRun^.result<>INVALID_SOCKET) and (pRun^.result<>0) then exit;
      if pRun^.result=SOCKET_ERROR then
      begin
        strcopy(pRun^.Info,'接收文件数据失败!');
        GetAPIErrCode(pRun);
      end;
      if pRun^.result=0 then
        strcopy(pRun^.Info,'文件接收完成!');
    end; //Frecv2
  FWriteFile:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'写文件失败!');
    end;//Fwritefile
  Frecv_S:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result=4 then exit;
      strcopy(pRun^.Info,'接收文件大小失败!(发送文件)');
    end;//Frecv_S
  FSetFilePointer_S:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'设置文件位置失败!(发送文件)');
    end;//FSetFilePointer_S
  FReadFile_S:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'读文件失败!(发送文件)');
    end;//Freadfile_s
  FReadFile_S1:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result>0 then exit;
      strcopy(pRun^.Info,'发送文件完成!(发送文件)');
    end;//Freadfile_s1
  Fsend_S:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'发送数据失败!(发送文件)');
    end;
  FGetFileAttributes:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'获取文件属性失败!');
    end;
  FDirectoryDecompression_1:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'开始解压缩文件..!');
      strcat(pRun^.Info,pFile^.fileName);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
    end;
  FDirectoryDecompression:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result>0 then
      begin
        strcopy(pRun^.Info,'解压缩文件完成!');
        strcat(pRun^.Info,pFile^.fileName);
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'解压缩文件失败!');
      strcat(pRun^.Info,pFile^.fileName);
    end;//
    Fdeletefile:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'删除文件失败!');
      strcat(pRun^.Info,pFile^.fileName);
    end;
  end;//case
  GetAPIErrCode(pRun);
  closesocket(pSock^.socketHandle);
  CloseHandle(pFile^.hFile);
  pThreadDataInfo^.active:=false;
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  dispose(pData);
  result:=false;
end;
procedure TransFileThread(pTransFileInfo:pointer);stdcall;

var
  pData:pTransFilesCS;
  buf:array[0..MAXBUF] of ansiChar;
  RequestFileInfo:stRequestFileInfo;
  wLen,NumberOfRead:cardinal;
  //fileSize,wLen,clientFileSize,NumberOfRead,fileSizeHigh,clientFileSizeHigh:cardinal;
  //RecvLen:integer;
begin
  pData:=pTransFileInfo;
  TransFileAPI(pData,FthreadStart);
  pData^.runAPI.result:=Recv(pData^.socket.socketHandle,RequestFileInfo,sizeof(RequestFileInfo),0);
  if not TransFileAPI(pData,FRecv) then exit;

  strcopy(pData^.fileInfo.FileName,RequestFileInfo.fileName);
  pData^.fileInfo.isUpLoad:=RequestFileInfo.bupLoad;

  pData^.fileInfo.hFile:=CreateFileA(RequestFileInfo.fileName,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,
      nil,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_ARCHIVE,0);
  if not TransFileAPI(pData,FCreateFile) then exit;

  pData^.fileInfo.fileSize:=GetFileSize(pData^.fileInfo.hFile,@pData^.fileInfo.fileSizeHigh);
  if not TransFileAPI(pData,FGetFileSize) then exit;

  if RequestFileInfo.bUpLoad then
    begin
      pData^.transRate.Transed:=pData^.fileInfo.FileSize;
      pData^.transRate.TransedHigh:=pData^.fileInfo.FileSizeHigh;
      
      pData^.runAPI.result:=SetFilePointer(pData^.fileInfo.hFile,0,nil,FILE_END);
      if not TransFileAPI(pData,FSetFilePointer) then exit;

      pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.fileInfo.ClientFileSize,4,0);
      if not TransFileAPI(pData,Frecv) then exit;

      pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.fileInfo.ClientFileSizeHigh,4,0);
      if not TransFileAPI(pData,Frecv) then exit;
      
      pData^.runAPI.result:=send(pData^.socket.socketHandle,pData^.fileInfo.fileSize,4,0);
      if not TransFileAPI(pData,Fsend) then exit;

      pData^.runAPI.result:=send(pData^.socket.socketHandle,pData^.fileInfo.fileSizeHigh,4,0);
      if not TransFileAPI(pData,Fsend) then exit;

      pData^.transRate.Speed:=0;
      while true do
      begin
        FillChar(buf,SizeOf(buf),0);
        pData^.runAPI.result:=Recv(pData^.socket.socketHandle,buf,sizeof(buf),0);
        if not TransFileAPI(pData,FRecv2) then break;

        if pData^.transRate.Transed+pData^.runAPI.result>$FFFFFFFF then
          pData^.transRate.TransedHigh:=pData^.transRate.TransedHigh+1;
        pData^.transRate.Transed:=pData^.transRate.Transed+pData^.runAPI.result;
        pData^.transRate.Speed:=pData^.transRate.Speed+pData^.runAPI.result;
        
        pData^.runAPI.result:=integer(WriteFile(pData^.fileInfo.hFile,Buf,pData^.runAPI.result,wLen,nil));
        if not TransFileAPI(pData,FWriteFile) then exit;
      end;//while
    end
    else begin
      pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.fileInfo.ClientFileSize,4,0);
      if not TransFileAPI(pData,Frecv_S) then exit;

      pData^.runAPI.result:=recv(pData^.socket.socketHandle,pData^.fileInfo.ClientFileSizeHigh,4,0);
      if not TransFileAPI(pData,Frecv_S) then exit;

       pData^.runAPI.result:=SetFilePointer(pData^.fileInfo.hFile,pData^.fileInfo.FileSize,@pData^.fileInfo.FileSizeHigh,FILE_BEGIN);
       if not TransFileAPI(pData,FSetFilePointer_S) then exit;

      pData^.transRate.Speed:=0;
      while true do
      begin
        pData^.runAPI.result:=integer(ReadFile(pData^.fileInfo.hFile,buf,sizeof(buf),NumberOfRead,nil));
        if not TransFileAPI(pData,FReadFile_S) then break;
        if not TransFileAPI(pData,FReadFile_S1) then break;

        pData^.runAPI.result:=send(pData^.socket.socketHandle,buf,NumberOfRead,0);
        if not TransFileAPI(pData,Fsend_S) then break;

        if pData^.transRate.Transed+pData^.runAPI.result>$FFFFFFFF then
          pData^.transRate.TransedHigh:=pData^.transRate.TransedHigh+1;
        pData^.transRate.Transed:=pData^.transRate.Transed+pData^.runAPI.result;
        pData^.transRate.Speed:=pData^.transRate.Speed+pData^.runAPI.result;
      end;//send(socket1,buf,NumberOfRead,0);
    end; //not if TransFileInfo.upLoad then
end;
function TransTypeAPI(pTransTypeInfo:pointer;FAPI:tAPIFlag):bool;stdcall;
var
  pData:pTypeCS;
  pRun:pRunAPIInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
begin
  result:=true;
  pData:=pTransTypeInfo;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pData^.runAPI.aAPI:=FAPI;
  pData^.runAPI.APIType:=Fsock;
  case pData^.runAPI.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'识别线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FRecv:
    begin
      pData^.runAPI.APIType:=Fsock;
      if (pData^.runAPI.result<>SOCKET_ERROR) and (pData^.runAPI.result<>0) then exit; //
      if  pData^.runAPI.result=SOCKET_ERROR then
        strcopy(pData^.runAPI.Info,'接收命令数据失败!错误代码是：');
      if  pData^.runAPI.result=0 then
        strcopy(pData^.runAPI.Info,'接收命令数据失败!Recv返回0!可能的错误是：');
    end;
  Fverify:
    begin
      pRun^.APIType:=Fwindows;
      if (pData^.oh.Version=con_CON_VER) and (pData^.oh.Encrpt=con_Encrpt) then
      begin
        strcopy(pRun^.Info,'数据端连接验证成功!');
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end//if pData^.oh.Version=con_CON_VER and pData^.oh.Encrpt=con_Encrpt then
      else begin
        strcopy(pData^.runAPI.Info,'数据端连接验证失败！');
        //SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        //closesocket(pSock^.socketHandle);
        //exit;
      end;//if pData^.oh.Version=con_CON_VER and pData^.oh.Encrpt=con_Encrpt then
    end;//Fverify
  FcreateThread:
    begin
      pData^.runAPI.APIType:=FWindows;
      if prun^.result<>0 then
      begin
        case pData^.TransType of
        FTypeClient:
          begin
            strcopy(pRun^.Info,'创建服务识别线程..!');
          end;//FTypeClient
        FTransFile:
          begin
           strcopy(pRun^.Info,'创建文件传输线程..!');
          end;//FTransFile
        FTransScr:
          begin
           strcopy(pRun^.Info,'创建图像传输线程..!');
          end;//FTransFile
        end;//case
        //sendmessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;//if
      strcopy(pRun^.Info,'创建线程失败!错误代码是：');
    end;//FcreateThread
  FthreadEnd:
    begin
      pData^.runAPI.APIType:=FWindows;
      pData^.runAPI.Info:='服务识别线程正常终止！';      
    end;//end
  end;//case
  GetAPIErrCode(pRun);
  if pData^.runAPI.aAPI<>FthreadEnd then
    closesocket(pSock^.socketHandle);
  pData^.thread.active:=false;
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  dispose(pData);
  result:=false;
end;
procedure TransTypeThread(pClientSocketInfo:pointer);stdcall;
var
  pData:pTypeCS;
  bTransType:TRequestType;
  pTF:pTransFilesCS;
  pTS:pTransScrCS;
  pGR:pGetRetCS;
  pRD:pRecvDataCS;
begin
  pData:=pClientSocketInfo;
  TransTypeAPI(pData,FthreadStart);
  pData^.runAPI.result:=Recv(pData^.socket.socketHandle,pData^.oh,sizeof(stOrdHeader),0);
  if not TransTypeAPI(pData,Frecv) then exit;
  //verify connect  validity:
  if not TransTypeAPI(pData,Fverify) then exit;

  if pData^.oh.order=o_TransFiles then bTransType:=RTransFile else
  if pData^.oh.order=o_Screen then bTransType:=RTransScr else bTransType:=RRecvData;
  
  case bTransType of
  RTransFile:
    begin
      new(pTF);
      zeromemory(pTF,sizeof(stTransFilesCS));
      pTF^.thread.threadType:=FTransFile;
      pTF^.sendMsg:=pData^.sendMsg;
      pTF^.socket:=pData^.socket;
      pTF^.thread.active:=true;

      pData^.TransType:=pTF^.thread.threadType;
      pData^.runAPI.result:=createthread(nil,0,@TransDirThread,pTF,0,pTF^.thread.threadID);
      if not TransTypeAPI(pData,Fcreatethread) then
      begin
        dispose(pTF);
        exit;
      end;
      pTF^.thread.hThread:=pData^.runAPI.result;
    end;
  RTransScr:
    begin
      new(pTS);
      zeromemory(pTS,sizeof(stTransScrCS));
      pTS^.thread.threadType:=FTransScr;
      pTS^.sendMsg:=pData^.sendMsg;
      pTS^.socket:=pData^.socket;
      pTS^.thread.active:=true;
      pTS^.order:=FScrStart;
      pData^.TransType:=pTS^.thread.threadType;
      //pData^.runAPI.result:=createthread(nil,0,@TransScrThread,pTS,0,pTS^.thread.threadID);
      pData^.runAPI.result:=createthread(nil,0,@GetScrThread,pTS,0,pTS^.thread.threadID);
      if not TransTypeAPI(pData,Fcreatethread) then
      begin
        dispose(pTS);
        exit;
      end;
      pTS^.thread.hThread:=pData^.runAPI.result;
    end;//FTransScr
  RRecvData:
    begin
      new(pRD);
      zeromemory(pRD,sizeof(stRecvDataCS));
      pRD^.thread.threadType:=FRecvData;
      pRD^.sendMsg:=pData^.sendMsg;
      pRD^.socket:=pData^.socket;
      pRD^.thread.active:=true;
      pRD^.oh:=pData^.oh;

      pData^.TransType:=pRD^.thread.threadType;
      pData^.runAPI.result:=createthread(nil,0,@RecvDataThread,pRD,0,pRD^.thread.threadID);
      if not TransTypeAPI(pData,Fcreatethread) then
      begin
        dispose(pRD);
        exit;
      end;
      pRD^.thread.hThread:=pData^.runAPI.result;
    end;//RTransData
  end;//case
  TransTypeAPI(pData,FthreadEnd);
  
end;

function TransDataAPI(pLisenSocketInfo:pointer;FAPI:TAPIFlag):bool;stdcall;
var
  pData:pListenSocket;
  pRun:pRunAPIInfo;
  pThreadDataInfo:pThreadInfo;
  pSock:pSocket;
  pMsg:pSendMsgTo;
begin
  result:=true;
  pThreadDataInfo:=pLisenSocketInfo;
  pData:=pLisenSocketInfo;
  pRun:=pRunAPIInfo(pansiChar(pData)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pData)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  pRun^.aAPI:=FAPI;
  case pRun^.aAPI of
  FthreadStart:
    begin
      pRun^.APIType:=Fwindows;
      strcopy(pRun^.Info,'主线程开始!');
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;
  FWSAStartup:
    begin
      pRun^.APIType:=Fsock;
      if  pRun^.result=0 then exit;
      strcopy(pRun^.Info,'初始化WS2_32.DLL失败!错误代码是：');
    end;//FWSAStartup
  Fsocket:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>INVALID_SOCKET then
      begin
        strcopy(pRun^.Info,'创建侦听socket!');
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'创建socket失败!!错误代码是：');
    end;//Fsocket
  Fsetsockopt:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'setsockopt失败!错误代码是：');
    end;//Fsetsockopt
  Fbind:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'绑定socket失败!错误代码是：');
    end;//Fbind
  Flisten:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>SOCKET_ERROR then
      begin
        strcopy(pRun^.Info,'服务处于等待中...');
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'侦听端口失败!错误代码是：');
    end;//Flisten
  Faccept:
    begin
      pRun^.APIType:=Fsock;
      if pRun^.result<>INVALID_SOCKET then exit;
      strcopy(pRun^.Info,'接受连接失败!错误代码是：');
      GetAPIErrCode(pRun);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;//Faccept
  FcreateThread:
    begin
      pRun^.APIType:=Fwindows;
      if pRun^.result<>0 then exit;
      strcopy(pRun^.Info,'创建线程失败!错误代码是：');
      GetAPIErrCode(pRun);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
      exit;
    end;//
  end;//case
  GetAPIErrCode(pRun);
  pThreadDataInfo^.active:=false;
  closesocket(pSock^.socketHandle);
  WSACleanup();
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  dispose(pData);
  result:=false;
end;
procedure TransDataThread(pLisenSocketInfo:pointer);stdcall;
var
  flag:bool;
  pData:pListenSocket;
  pClient:pTypeCS;
begin
  with pData^.runAPI,pData^.socket do
  begin
    pData:=pLisenSocketInfo;
    TransDataAPI(pData,FthreadStart);
    pData^.runAPI.result:=WSAStartup($0202,pData^.wsadata);
    if not TransDataAPI(pData,FWSAStartup) then exit;

    pData^.runAPI.result:=socket(AF_INET, SOCK_STREAM, 0); //SOCK_DGRAM
    if not TransDataAPI(pData,Fsocket) then exit;
    pData^.socket.socketHandle:=pData^.runAPI.result;

    pData^.runAPI.result:=setsockopt(pData^.socket.socketHandle,SOL_SOCKET,SO_REUSEADDR,@flag,sizeof(flag));
    if not TransDataAPI(pData,Fsetsockopt) then exit;

    zeromemory(@(pData^.socket.addr),sizeof(pData^.socket.addr));
    pData^.socket.addr.sin_family:=AF_INET;
    pData^.socket.addr.sin_port:=htons(PORT);
    pData^.socket.addr.sin_addr.s_addr:=htonl(INADDR_ANY);

    pData^.runAPI.result:=bind(pData^.socket.socketHandle,pData^.socket.addr,sizeof(pData^.socket.addr));
    if not TransDataAPI(pData,Fbind) then exit;
    pData^.runAPI.result:=listen(pData^.socket.socketHandle,5);
    if not TransDataAPI(pData,Flisten) then exit;
  end;//with
  while true do
  begin
    new(pClient);
    pClient^.thread.active:=true;
    pClient^.thread.threadType:=FTypeClient;
    pClient^.sendMsg.hform:=pData^.sendMsg.hform;
    pClient^.sendMsg.msgType:=pData^.sendMsg.msgType;
    zeromemory(@(pClient^.socket.Addr),sizeof(pClient^.socket.addr));
    pClient^.socket.AddrLen:=sizeof(pClient^.socket.addr);

    //pClient^.socket.socketHandle:=Accept(pData^.socket.socketHandle,@(pClient^.socket.Addr),@(pClient^.socket.AddrLen));
    pData^.runAPI.result:=Accept(pData^.socket.socketHandle,@(pClient^.socket.Addr),@(pClient^.socket.AddrLen));
    if not TransDataAPI(pData,Faccept) then
    begin
      dispose(pClient);
      if pData^.runAPI.errCode=WSAENOTSOCK then
      begin
        pData^.thread.active:=false;
        closesocket(pData^.socket.socketHandle);
        WSACleanup();
        dispose(pData);
        exit;
      end
      else begin
        continue;
      end;//if
    end;
    pClient^.socket.socketHandle:=pData^.runAPI.result;
    pData^.runAPI.result:=createthread(nil,0,@TransTypeThread,pClient,0,pClient^.thread.threadID);
    if not TransDataAPI(pData,Fcreatethread) then
    begin
      dispose(pClient);
      continue;
    end;
    pClient^.thread.hThread:=pData^.runAPI.result;
  end;//while
end;
procedure GetAPIErrCode(pRun:pRunAPIInfo);stdcall;
var
    ErrMsg:Array[0..255] of ansiChar;
begin
  case pRun^.APIType of
  Fwindows:
    begin
      pRun^.errCode:=GetLastError;
      FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS, //FORMAT_MESSAGE_ARGUMENT_ARRAY
      nil,pRun^.errCode,0,ErrMsg,sizeof(ErrMsg),nil); //MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
    end;
  Fsock:
    begin
      pRun^.errCode:=WSAGetLastError;
      strcopy(ErrMsg,'中断连接!');
      case pRun^.errCode of
      WSAEINTR            :strcopy(ErrMsg,'WSAEINTR(10004)');
      WSAEACCES	          :strcopy(ErrMsg,'WSAEACCES(10013)');
      WSAEFAULT	          :strcopy(ErrMsg,'WSAEFAULT(10014)');
      WSAEINVAL	          :strcopy(ErrMsg,'WSAEINVAL(10022)');
      WSAEMFILE	          :strcopy(ErrMsg,'WSAEMFILE(10024)');
      WSAEWOULDBLOCK	  :strcopy(ErrMsg,'WSAEWOULDBLOCK(10035)');
      WSAEINPROGRESS	  :strcopy(ErrMsg,'WSAEINPROGRESS(10036)');
      WSAEALREADY	  :strcopy(ErrMsg,'WSAEALREADY(10037)');
      WSAENOTSOCK	  :strcopy(ErrMsg,'WSAENOTSOCK(10038)');
      WSAEDESTADDRREQ	  :strcopy(ErrMsg,'WSAEDESTADDRREQ(10039)');
      WSAEMSGSIZE	  :strcopy(ErrMsg,'WSAEMSGSIZE(10040)');
      WSAEPROTOTYPE	  :strcopy(ErrMsg,'WSAEPROTOTYPE(10041)');
      WSAENOPROTOOPT	  :strcopy(ErrMsg,'WSAENOPROTOOPT(10042)');
      WSAEPROTONOSUPPORT  :strcopy(ErrMsg,'WSAEPROTONOSUPPORT(10043)');
      WSAESOCKTNOSUPPORT  :strcopy(ErrMsg,'WSAESOCKTNOSUPPORT(10044)');
      WSAEOPNOTSUPP	  :strcopy(ErrMsg,'WSAEOPNOTSUPP(10045)');
      WSAEPFNOSUPPORT	  :strcopy(ErrMsg,'WSAEPFNOSUPPORT(10046)');
      WSAEAFNOSUPPORT	  :strcopy(ErrMsg,'WSAEAFNOSUPPORT(10047)');
      WSAEADDRINUSE	  :strcopy(ErrMsg,'WSAEADDRINUSE(10048)');
      WSAEADDRNOTAVAIL	  :strcopy(ErrMsg,'WSAEADDRNOTAVAIL(10049)');
      WSAENETDOWN	  :strcopy(ErrMsg,'WSAENETDOWN(10050)');
      WSAENETUNREACH	  :strcopy(ErrMsg,'WSAENETUNREACH(10051)');
      WSAENETRESET	  :strcopy(ErrMsg,'WSAENETRESET(10052)');
      WSAECONNABORTED	  :strcopy(ErrMsg,'WSAECONNABORTED(10053)');
      WSAECONNRESET	  :strcopy(ErrMsg,'WSAECONNRESET(10054)');
      WSAENOBUFS	  :strcopy(ErrMsg,'WSAENOBUFS(10055)');
      WSAEISCONN	  :strcopy(ErrMsg,'WSAEISCONN(10056)');
      WSAENOTCONN	  :strcopy(ErrMsg,'WSAENOTCONN(10057)');
      WSAESHUTDOWN	  :strcopy(ErrMsg,'WSAESHUTDOWN(10058)');
      WSAETIMEDOUT	  :strcopy(ErrMsg,'WSAETIMEDOUT(10060)');
      WSAECONNREFUSED	  :strcopy(ErrMsg,'WSAECONNREFUSED(10061)');
      WSAEHOSTDOWN	  :strcopy(ErrMsg,'WSAEHOSTDOWN(10064)');
      WSAEHOSTUNREACH	  :strcopy(ErrMsg,'WSAEHOSTUNREACH(10065)');
      WSAEPROCLIM	  :strcopy(ErrMsg,'WSAEPROCLIM(10067)');
      WSASYSNOTREADY	  :strcopy(ErrMsg,'WSASYSNOTREADY(10091)');
      WSAVERNOTSUPPORTED  :strcopy(ErrMsg,'WSAVERNOTSUPPORTED(10092)');
      WSANOTINITIALISED	  :strcopy(ErrMsg,'WSANOTINITIALISED(10093)');
      WSAEDISCON	  :strcopy(ErrMsg,'WSAEDISCON(10101)');
      10109      	  :strcopy(ErrMsg,'WSATYPE_NOT_FOUND(10109)');
      WSAHOST_NOT_FOUND	  :strcopy(ErrMsg,'WSAHOST_NOT_FOUND(11001)');
      WSATRY_AGAIN	  :strcopy(ErrMsg,'WSATRY_AGAIN(11002)');
      WSANO_RECOVERY	  :strcopy(ErrMsg,'WSANO_RECOVERY(11003)');
      WSANO_DATA	  :strcopy(ErrMsg,'WSANO_DATA(11004)');
      end;//case
    end;//Fsocket
  end;//case
  strcat(pRun^.Info,ErrMsg);
end;
{
function RunAPIOK(pThreadDataInfo:pointer):bool;stdcall;
var
  pThread:pThreadInfo;
  pRun:pRunAPIInfo;
  pMsg:pSendMsgTo;
  pSock:pSocket;
  pFile:pFileInfo;
  pBmp:^HBITMAP;
begin
  result:=true;
  //pRun:=pointer(integer(pThreadDataInfo)+sizeof(TThreadType));
  //pMsg:=pointer(integer(pThreadDataInfo)+sizeof(TThreadType)+sizeof(stRunAPIInfo));
  //pSock:=pointer(integer(pThreadDataInfo)+sizeof(TThreadType)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  //pThread:=pointer(integer(pSock)+sizeof(stSocket));
  pThread:=pThreadDataInfo;
  pRun:=pRunAPIInfo(pansiChar(pThreadDataInfo)+sizeof(stThreadInfo));
  pMsg:=pSendMsgTo(pansiChar(pThreadDataInfo)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo));
  pSock:=pSocket(pansiChar(pThreadDataInfo)+sizeof(stThreadInfo)+sizeof(stRunAPIInfo)+sizeof(stSendMsgTo));
  case pThread^.threadType of
  FTransFile:
    begin
      pFile:=pFileInfo(pansiChar(pSock)+sizeof(stSocket));
    end;//
  FTransScr:
    begin
      pBmp:=pointer(pansiChar(pSock)+sizeof(stSocket));
    end;
  FTypeClient:
    begin
      //
    end;//
  end;//case
  case pRun^.aAPI of
    FWSAStartup:
    begin
      if  pRun^.result=0 then exit;
      strcopy(pRun^.Info,'初始化WS2_32.DLL失败!错误代码是：');
      GetAPIErrCode(pRun);


      WSACleanup();//终止WS2_32.DLL的使用

    end;//FWSAStartup
    Fsocket:
    begin
      if psock^.socketHandle<>INVALID_SOCKET then
      begin
        strcopy(pRun^.Info,'创建侦听socket!');
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'创建socket失败!!错误代码是：');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      WSACleanup();
    end;//Fsocket
    Fsetsockopt:
    begin
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'setsockopt失败!错误代码是：');
      GetAPIErrCode(pRun);


      closesocket(pSock^.socketHandle);
      WSACleanup();

    end;//Fsetsockopt
    Fbind:
    begin
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'绑定socket失败!错误代码是：');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      WSACleanup();

    end;//Fbind
    Flisten:
    begin
      if pRun^.result<>SOCKET_ERROR then
      begin
        strcopy(pRun^.Info,'服务处于等待中...');
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'侦听端口失败!错误代码是：');
      GetAPIErrCode(pRun);


      closesocket(pSock^.socketHandle);
      WSACleanup();

    end;//Flisten
    Faccept:
    begin
      if psock^.socketHandle<>INVALID_SOCKET then
      begin
        //strcopy(pRun^.Info,'接受连接..!');
       // sendmessage(pMsg^.hform,pMsg^.msgType,integer(pThreadDataInfo),0);
        exit;//
      end;
      strcopy(pRun^.Info,'接受连接失败!错误代码是：');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);

    end;// Faccept
    FcreateThread:
    begin

      if pThread^.hThread<>0 then
      begin
        case pThread^.threadType of
        FTypeClient:
          begin
            strcopy(pRun^.Info,'创建服务识别线程..!');
          end;//FTypeClient
        FTransFile:
          begin
           strcopy(pRun^.Info,'创建文件传输线程..!');
          end;//FTransFile
        FTransScr:
          begin
           strcopy(pRun^.Info,'创建图像传输线程..!');
          end;//FTransFile
        end;//case
        sendmessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;//
      end;
      strcopy(pRun^.Info,'创建线程失败!错误代码是：');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);

    end;
    Frecv:
    begin
      if pRun^.result<>INVALID_SOCKET then exit; //
      strcopy(pRun^.Info,'接收数据失败!错误代码是：');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);

    end;//Frecv
    FcreateFile:
    begin
      if (pRun^.result<>-1) then exit;
      GetAPIErrCode(pRun);
      strcopy(pRun^.Info,'创建文件失败!错误代码是：');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end; //FcreateFile
    FGetFileSize:
    begin
      if pRun^.result<>-1 then exit;
      if (pRun^.result=-1) and (GetLastError()=NO_ERROR) then exit;
      strcopy(pRun^.Info,'获取文件大小失败!');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//FGetFileSize
    FSetFilePointer:
    begin
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'设置文件位置失败!!');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;
    Fsend:
    begin
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'发送数据失败!');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      case pThread^.threadType of
        FTransFile:
        begin
          CloseHandle(pFile^.hFile);
        end; // FTransFile
      end;
    end;//Fsend
    FRecv2:
    begin
      if (pRun^.result<>INVALID_SOCKET) and (pRun^.result<>0) then exit;
      if pRun^.result=SOCKET_ERROR then
      begin
        strcopy(pRun^.Info,'接收文件数据失败!');
        GetAPIErrCode(pRun);
      end;
      if pRun^.result=0 then
        strcopy(pRun^.Info,'文件接收完成!');

      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//FRecv2
    FWriteFile:
    begin
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'写文件失败!');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//FWriteFile
    Frecv_S:
    begin
      if pRun^.result=4 then exit;
      strcopy(pRun^.Info,'接收文件大小失败!(发送文件)');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//Frecv_S
    FSetFilePointer_S:
    begin
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'设置文件位置失败!(发送文件)');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//FSetFilePointer_S
    FReadFile_S:
    begin
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'读文件失败!(发送文件)');
      GetAPIErrCode(pRun);

      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//FReadFile_S
    FReadFile_S1:
    begin
      if pRun^.result>0 then exit;
      strcopy(pRun^.Info,'发送文件完成!(发送文件)');
      GetAPIErrCode(pRun);


      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//FReadFile_S1
    Fsend_S:
    begin
      if pRun^.result<>SOCKET_ERROR then exit;
      strcopy(pRun^.Info,'发送数据失败!(发送文件)');
      GetAPIErrCode(pRun);


      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//Fsend_S
    FGetFileAttributes:
    begin
      if pRun^.result<>-1 then exit;
      strcopy(pRun^.Info,'获取文件属性失败!');
      GetAPIErrCode(pRun);


      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//Fsend_S
    FDirectoryCompression_1:
    begin
      //if pRun^.result>0 then exit;
      strcopy(pRun^.Info,'开始压缩文件..!');
      GetAPIErrCode(pRun);
      strcat(pRun^.Info,pFile^.fileName);


    end;//Fsend_S
    FDirectoryCompression:
    begin
      if pRun^.result>0 then
      begin
        strcopy(pRun^.Info,'压缩文件完成!');

        strcat(pRun^.Info,pFile^.fileName);
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'压缩文件失败!');
      strcat(pRun^.Info,pFile^.fileName);
      //GetAPIErrCode(pRun);


      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//Fsend_S
    FDirectoryDecompression_1:
    begin
      //if pRun^.result>0 then exit;
      strcopy(pRun^.Info,'开始解压缩文件..!');
      strcat(pRun^.Info,pFile^.fileName);
      SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));

    end;//Fsend_S
    FDirectoryDecompression:
    begin
      if pRun^.result>0 then
      begin
        strcopy(pRun^.Info,'解压缩文件完成!');
        strcat(pRun^.Info,pFile^.fileName);
        SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
        exit;
      end;
      strcopy(pRun^.Info,'解压缩文件失败!');
      strcat(pRun^.Info,pFile^.fileName);


      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//Fsend_S
    Fdeletefile:
    begin
      if pRun^.result=1 then exit;
      strcopy(pRun^.Info,'删除文件失败!');
      strcat(pRun^.Info,pFile^.fileName);
      GetAPIErrCode(pRun);


      closesocket(pSock^.socketHandle);
      CloseHandle(pFile^.hFile);

    end;//Fsend_S
  FCreateDIBSection:
    begin
      exit;
    end;//FCreateDIBSection
  end;//case
  pThread^.active:=false;
  SendMessage(pMsg^.hform,pMsg^.msgType,0,integer(pData));
  dispose(pThreadDataInfo);
  result:=false;
end;
}
end.

