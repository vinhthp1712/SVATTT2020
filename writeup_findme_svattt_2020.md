# ASCIS 2020 QUALIFICATION ROUND

## Findme
Ở bài này chương trình sẽ yêu cầu chúng ta nhập key. Chương trình dùng RPC để send key mình để check. Nếu key đúng thì sẽ in ra Congratulation rồi in ra flag. Dưới đây là đoạn F5 IDA =)).
```
if ( !SetConsoleCtrlHandler(HandlerRoutine, 1) )
    return 1;
  sub_4010B0("___________.__            .___                 \n");
  sub_4010B0("\\_   _____/|__| ____    __| _/  _____   ____  \n");
  sub_4010B0(" |    __)  |  |/    \\  / __ |  /     \\_/ __ \\ \n");
  sub_4010B0(" |    \\    |  |   |  \\/ /_/|  |  Y Y  \\  ___/ \n");
  sub_4010B0(" \\___ /    |__|___|  /\\____|  |__|_|  /\\___  >\n");
  sub_4010B0("    \\/            \\/      \\/        \\/     \\/ \n");
  StringBinding = 0;
  v4 = RpcStringBindingComposeA(0, "ncacn_np", 0, "\\pipe\\svattt2020", 0, &StringBinding);
  if ( v4 )
    goto LABEL_14;
  v5 = RpcBindingFromStringBindingA(StringBinding, &Binding);
  if ( v5 )
  {
LABEL_15:
    v10 = sub_403ABF(v5);
LABEL_16:
    result = sub_403ABF(v10);
    goto LABEL_17;
  }
  sub_4010B0("Input password: ");
  sub_402500(v13, 0, 256);
  v6 = sub_403B9D(0);
  sub_4050B5(v13, 256, v6);
  v7 = &v13[strlen(v13)] - &v13[1];
  if ( v7 >= 0x100 )
  {
    v4 = sub_401784(v7, &v13[1]);
LABEL_14:
    v5 = sub_403ABF(v4);
    goto LABEL_15;
  }
  v13[v7] = 0;
  ms_exc.registration.TryLevel = 0;
  sub_4010B0("Checking...\n");
  if ( (unsigned __int8)sub_401010((unsigned int)v13) )
  {
    v8 = (LPVOID *)sub_4050DD(4);
    *v8 = 0;
    v12 = 0;
    sub_401040((unsigned int)v13);
    v9 = *v8;
    sub_4010B0("Congratulation: %s\n");
    sub_4050C0(*v8);
    sub_4050C0(v8);
  }
  else
  {
    sub_4010B0("Sorry, incorrect password\n");
  }
  ms_exc.registration.TryLevel = 1;
  sub_401070();
  Sleep(0x3E8u);
  ms_exc.registration.TryLevel = -2;
  v10 = RpcStringFreeA(&StringBinding);
  if ( v10 )
    goto LABEL_16;
  result = RpcBindingFree(&Binding);
  if ( result )
  {
LABEL_17:
    sub_403ABF(result);
    JUMPOUT(*(_DWORD *)algn_40161A);
  }
  return result;
```
Có lẽ do mình dùng IDA debug ngay hàm main mà không qua cái start nên mất một lúc rất lâu để debug tìm xem chương trình này sẽ RPC đến đâu :(. Trước khi vào hàm main chương trình sẽ create 1 process mới rồi để nó vào trong thư mục temp.

```
 v16 = GetTempPathA(0x200u, &Buffer);
  if ( v16 > 0x200
    || !v16
    || !GetTempFileNameA(&Buffer, 0, 0, v15)
    || (v17 = CreateFileA(v15, 0xC0000000, 0, 0, 2u, 0x80u, 0), v17 == (HANDLE)-1)
    || !WriteFile(v17, lpBuffer, v4, &NumberOfBytesWritten, 0)
    || !CloseHandle(v17)
    || (lpFileName = v15, !CreateProcessA(v15, 0, 0, 0, 1, 0, 0, 0, &StartupInfo, &ProcessInformation)) )
  {
LABEL_24:
    sub_403ABF(1u);
    __debugbreak();
    JUMPOUT(*(_DWORD *)main);
  }
```
Bây giờ thì chúng ta dump file kia ra rồi reverse để tìm key thôi xD.
Chương trình được dump ra sẽ đợi chương trình phía trên send data khi input key.

```
int __usercall sub_401650@<eax>(RPC_STATUS a1@<esi>)
{
  RPC_STATUS v1; // eax
  RPC_STATUS v2; // eax

  hEvent = CreateEventA(0, 1, 0, 0);
  if ( hEvent )
  {
    v1 = RpcServerUseProtseqEpA("ncacn_np", 0xAu, "\\pipe\\svattt2020", 0);
    if ( v1 )
    {
      v2 = sub_403AEF(v1);
    }
    else
    {
      v2 = RpcServerRegisterIf2(&unk_412B80, 0, 0, 0x10u, 0x4D2u, 0xFFFFFFFF, IfCallbackFn);
      if ( !v2 )
      {
        a1 = RpcServerListen(1u, 0x4D2u, 1u);
        WaitForSingleObject(hEvent, 0xFFFFFFFF);
        Sleep(0x3E8u);
        RpcMgmtStopServerListening(&unk_412B80);
        RpcServerUnregisterIf(&unk_412B80, 0, 0);
        CloseHandle(hEvent);
        if ( !a1 )
          return 0;
LABEL_8:
        sub_403AEF(a1);
        JUMPOUT(*(_DWORD *)algn_40170D);
      }
    }
    sub_403AEF(v2);
    goto LABEL_8;
  }
  return 0;
}
```
Khi input key và send data sang chương trình này thì đến đoạn check key với đống xor xủng.

```
  if ( strlen((const char *)a1) != 16 )
    return 0;
  v1 = *(_BYTE *)(a1 + 14);
  v32 = *(_BYTE *)(a1 + 12);
  v31 = v1;
  v2 = *(_BYTE *)(a1 + 15) ^ v1;
  v3 = *(_BYTE *)(a1 + 13);
  v4 = v3 ^ v2;
  v5 = *(_BYTE *)(a1 + 6);
  v6 = v32 ^ v3 ^ v2;
  v33 = *(_BYTE *)(a1 + 10);
  v35 = *(_BYTE *)(a1 + 11);
  v43 = *(_BYTE *)(a1 + 9);
  v44 = *(_BYTE *)(a1 + 8);
  v34 = *(_BYTE *)(a1 + 5);
  v42 = *(_BYTE *)(a1 + 4);
  v29 = v32 ^ v2;
  v40 = *(_BYTE *)(a1 + 1);
  v41 = *(_BYTE *)a1;
  v38 = *(_BYTE *)(a1 + 3);
  v36 = *(_BYTE *)(a1 + 2);
  v24 = v43 ^ v40 ^ v36 ^ v32 ^ v2;
  v37 = *(_BYTE *)(a1 + 7);
  v25 = v43 ^ *(_BYTE *)a1 ^ v33 ^ v5 ^ v37 ^ v3 ^ v35;
  v26 = v44 ^ v42 ^ v40 ^ *(_BYTE *)a1 ^ v37 ^ v3 ^ v35;
  v30 = *(_BYTE *)(a1 + 15) ^ v32;
  v39 = v3 ^ v32 ^ v35;
  v27 = v43 ^ v44 ^ *(_BYTE *)a1 ^ v36 ^ v37 ^ v3 ^ v2;
  v28 = v31 ^ v3 ^ v32 ^ v35 ^ v44 ^ v42 ^ *(_BYTE *)a1 ^ v33 ^ v36;
  v7 = (v35 ^ (unsigned __int8)(v43 ^ v34 ^ v40 ^ *(_BYTE *)a1 ^ v33 ^ v5 ^ v38 ^ v36 ^ v2)) == 117;
  v8 = 0;
  v9 = (v35 ^ (unsigned __int8)(v43 ^ v44 ^ v34 ^ v42 ^ v40 ^ *(_BYTE *)a1 ^ v6)) == 49 && v7;
  if ( (v44 ^ (unsigned __int8)(v34 ^ v42 ^ v5 ^ v38 ^ v37 ^ v6)) == 82 )
    v8 = v9;
  v10 = 0;
  v11 = (v35 ^ (unsigned __int8)(v43 ^ v44 ^ v34 ^ v40 ^ v41 ^ v33 ^ v4)) == 102 && v8;
  v12 = *(_BYTE *)(a1 + 6);
  if ( (v35 ^ (unsigned __int8)(v43 ^ v34 ^ v42 ^ v40 ^ v38 ^ v36 ^ v30)) == 115 )
    v10 = v11;
  v13 = 0;
  v14 = (v44 ^ (unsigned __int8)(v42 ^ v41 ^ v12 ^ v38 ^ v36 ^ v29)) == 56 && v10;
  if ( v28 == 50 )
    v13 = v14;
  v15 = (v42 ^ (unsigned __int8)(v33 ^ v12 ^ v38 ^ v36 ^ v39)) == 110 && v13;
  v16 = 0;
  if ( v27 == 7 )
    v16 = v15;
  v17 = 0;
  v18 = (v31 ^ (unsigned __int8)(v32 ^ v35 ^ v42 ^ v41 ^ v33 ^ v12 ^ v36)) == 7 && v16;
  if ( v26 == 16 )
    v17 = v18;
  v19 = 0;
  v20 = ((v43 ^ (unsigned __int8)(v44 ^ v41 ^ v37 ^ v39)) == 29) & v17;
  if ( v25 == 7 )
    v19 = v20;
  v21 = 0;
  v22 = ((v43 ^ (unsigned __int8)(v34 ^ v42 ^ v38 ^ v30)) == 25) & v19;
  if ( v24 == 78 )
    v21 = v22;
  return ((v31 ^ (unsigned __int8)(v34 ^ v40 ^ v38 ^ v37)) == 48) & v21;
```
Key sẽ có độ dài là 16. Nhờ nhà ảo thuật tài ba pilot nguyễn đã hô biến từ 16 phương trình xuống 11 phương trình làm team mình giải bài này mất thêm 2h để debug tìm lỗi.Để giải hệ phương trình kia thì mình dùng z3, nhét vào 1s ra luôn key =)).

```
from z3 import *

k0 = BitVec('k0', 8)
k1 = BitVec('k1', 8)
k2 = BitVec('k2', 8)
k3 = BitVec('k3', 8)
k4 = BitVec('k4', 8)
k5 = BitVec('k5', 8)
k6 = BitVec('k6', 8)
k7 = BitVec('k7', 8)
k8 = BitVec('k8', 8)
k9 = BitVec('k9', 8)
k10 = BitVec('k10', 8)
k11 = BitVec('k11', 8)
k12 = BitVec('k12', 8)
k13 = BitVec('k13', 8)
k14 = BitVec('k14', 8)
k15 = BitVec('k15', 8)

solve([k14 ^ k5 ^ k1 ^ k3 ^ k7 == 48,k9 ^ k5 ^ k4 ^ k3 ^ k15 ^ k12 == 25,k9 ^ k8 ^ k0 ^ k7 ^ k13 ^ k12 ^ k11 == 29,k14 ^ k12 ^ k11 ^ k4 ^ k0 ^ k10 ^ k6 ^ k2 == 7,k4 ^ k10 ^ k6 ^ k3 ^ k2 ^ k13 ^ k12 ^ k11 == 110,k8 ^ k4 ^ k0 ^ k6 ^ k3 ^ k2 ^ k12 ^ k14 ^ k15 == 56,k11 ^ k9 ^ k5 ^ k4 ^ k1 ^ k3 ^ k2 ^ k15 ^ k12 == 115,k11 ^ k9 ^ k8 ^ k5 ^ k1 ^ k0 ^ k10 ^ k13 ^ k14 ^ k15 == 102,k8 ^ k5 ^ k4 ^ k6 ^ k3 ^ k7 ^ k12 ^ k13 ^ k14 ^ k15 == 82,k11 ^ k9 ^ k8 ^ k5 ^ k4 ^ k1 ^ k0 ^ k12 ^ k13 ^ k14 ^ k15 == 49,k11 ^ k9 ^ k5 ^ k1 ^ k0 ^ k10 ^ k6 ^ k3 ^ k2 ^ k14 ^ k15 == 117,k14 ^ k13 ^ k12 ^ k11 ^ k8 ^ k4 ^ k0 ^ k10 ^ k2 == 50,k9 ^ k8 ^ k0 ^ k2 ^ k7 ^ k13 ^ k14 ^ k15 == 7,k8 ^ k4 ^ k1 ^ k0 ^ k7 ^ k13 ^ k11 == 16,k9 ^ k0 ^ k10 ^ k6 ^ k7 ^ k13 ^ k11 == 7,k9 ^ k1 ^ k2 ^ k12 ^ k14 ^ k15== 78])
```



