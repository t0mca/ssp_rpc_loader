/* this ALWAYS GENERATED file contains the RPC client stubs */

/* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 03:14:07 2038
*/
/* Compiler settings for sspi.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if defined(_M_AMD64)


#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/

#include <string.h>

#include "sspi_h.h"

#define TYPE_FORMAT_STRING_SIZE   985                               
#define PROC_FORMAT_STRING_SIZE   1221                              
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _sspi_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } sspi_MIDL_TYPE_FORMAT_STRING;

typedef struct _sspi_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } sspi_MIDL_PROC_FORMAT_STRING;

typedef struct _sspi_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } sspi_MIDL_EXPR_FORMAT_STRING;


static const RPC_SYNTAX_IDENTIFIER  _RpcTransferSyntax = 
{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}};

static const RPC_SYNTAX_IDENTIFIER  _NDR64_RpcTransferSyntax = 
{{0x71710533,0xbeba,0x4937,{0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36}},{1,0}};



extern const sspi_MIDL_TYPE_FORMAT_STRING sspi__MIDL_TypeFormatString;
extern const sspi_MIDL_PROC_FORMAT_STRING sspi__MIDL_ProcFormatString;
extern const sspi_MIDL_EXPR_FORMAT_STRING sspi__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   0            


/* Standard interface: DefaultIfName, ver. 1.0,
   GUID={0x4f32adc8,0x6052,0x4a04,{0x87,0x01,0x29,0x3c,0xcf,0x20,0x96,0xf0}} */

 extern const MIDL_STUBLESS_PROXY_INFO DefaultIfName_ProxyInfo;
handle_t default_IfHandle;


static const RPC_CLIENT_INTERFACE DefaultIfName___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x4f32adc8,0x6052,0x4a04,{0x87,0x01,0x29,0x3c,0xcf,0x20,0x96,0xf0}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    0,
    0,
    0,
    &DefaultIfName_ProxyInfo,
    0x02000000
    };
RPC_IF_HANDLE DefaultIfName_v1_0_c_ifspec = (RPC_IF_HANDLE)& DefaultIfName___RpcClientInterface;

extern const MIDL_STUB_DESC DefaultIfName_StubDesc;

static RPC_BINDING_HANDLE DefaultIfName__MIDL_AutoBindHandle;


long Proc0_SspirConnectRpc( 
    /* [string][unique][in] */ unsigned char *arg_1,
    /* [in] */ long arg_2,
    /* [out] */ long *arg_3,
    /* [out] */ long *arg_4,
    /* [context_handle][out] */ void **arg_5)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  0,
                  0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4,
                  arg_5);
    return ( long  )_RetVal.Simple;
    
}


long Proc1_SspirDisconnectRpc( 
    /* [context_handle][out][in] */ void **arg_0)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  1,
                  0,
                  arg_0);
    return ( long  )_RetVal.Simple;
    
}


long Proc2_SspirDisconnectRpc( 
    /* [context_handle][out][in] */ void **arg_0)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  2,
                  0,
                  arg_0);
    return ( long  )_RetVal.Simple;
    
}


long Proc3_SspirCallRpc( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ long arg_1,
    /* [size_is][in] */ unsigned char *arg_2,
    /* [out] */ long *arg_3,
    /* [size_is][size_is][ref][out] */ unsigned char **arg_4,
    /* [out] */ struct Struct_144_t *arg_5)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  3,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4,
                  arg_5);
    return ( long  )_RetVal.Simple;
    
}


long Proc4_SspirAcquireCredentialsHandle( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [unique][in] */ struct Struct_222_t *arg_2,
    /* [in] */ struct Struct_222_t *arg_3,
    /* [in] */ long arg_4,
    /* [unique][in] */ struct Struct_248_t *arg_5,
    /* [in] */ struct Struct_282_t *arg_6,
    /* [in] */ hyper arg_7,
    /* [in] */ hyper arg_8,
    /* [in] */ long arg_9,
    /* [out] */ struct Struct_304_t *arg_10,
    /* [out] */ struct Struct_316_t *arg_11,
    /* [in] */ struct Struct_144_t *arg_12,
    /* [out] */ struct Struct_144_t *arg_13)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  4,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4,
                  arg_5,
                  arg_6,
                  arg_7,
                  arg_8,
                  arg_9,
                  arg_10,
                  arg_11,
                  arg_12,
                  arg_13);
    return ( long  )_RetVal.Simple;
    
}


long Proc5_SspirFreeCredentialsHandle( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ struct Struct_304_t *arg_2,
    /* [out] */ struct Struct_144_t *arg_3)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  5,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3);
    return ( long  )_RetVal.Simple;
    
}


long Proc6_SspirProcessSecurityContext( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [out][in] */ long *arg_2,
    /* [unique][in] */ struct Struct_222_t *arg_3,
    /* [in] */ struct Struct_304_t *arg_4,
    /* [in] */ struct Struct_304_t *arg_5,
    /* [in] */ long arg_6,
    /* [in] */ long arg_7,
    /* [size_is][unique][in] */ unsigned char *arg_8,
    /* [string][unique][in] */ wchar_t *arg_9,
    /* [in] */ struct Struct_446_t *arg_10,
    /* [ref][in] */ struct Struct_516_t *arg_11,
    /* [out] */ struct Struct_446_t *arg_12,
    /* [ref][out] */ struct Struct_516_t **arg_13,
    /* [out] */ struct Struct_128_t *arg_14,
    /* [out] */ struct Struct_304_t *arg_15,
    /* [out] */ long *arg_16,
    /* [out] */ struct Struct_316_t *arg_17,
    /* [out] */ long *arg_18,
    /* [in] */ struct Struct_144_t *arg_19,
    /* [out] */ struct Struct_144_t *arg_20)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  6,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4,
                  arg_5,
                  arg_6,
                  arg_7,
                  arg_8,
                  arg_9,
                  arg_10,
                  arg_11,
                  arg_12,
                  arg_13,
                  arg_14,
                  arg_15,
                  arg_16,
                  arg_17,
                  arg_18,
                  arg_19,
                  arg_20);
    return ( long  )_RetVal.Simple;
    
}


long Proc7_SspirDeleteSecurityContext( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ struct Struct_304_t *arg_2,
    /* [out] */ struct Struct_144_t *arg_3)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  7,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3);
    return ( long  )_RetVal.Simple;
    
}


long Proc8_SspirSslQueryCredentialsAttributes( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ struct Struct_304_t *arg_2,
    /* [in] */ long arg_3,
    /* [switch_is][out] */ union union_624 *arg_4)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  8,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4);
    return ( long  )_RetVal.Simple;
    
}


long Proc9_SspirNegQueryContextAttributes( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ struct Struct_304_t *arg_2,
    /* [in] */ long arg_3,
    /* [switch_is][out] */ union union_750 *arg_4)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  9,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4);
    return ( long  )_RetVal.Simple;
    
}


long Proc10_SspirSslSetCredentialsAttributes( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ struct Struct_304_t *arg_2,
    /* [in] */ struct Struct_888_t *arg_3)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  10,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3);
    return ( long  )_RetVal.Simple;
    
}


long Proc11_SspirApplyControlToken( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ struct Struct_304_t *arg_2,
    /* [in] */ struct Struct_446_t *arg_3)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  11,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3);
    return ( long  )_RetVal.Simple;
    
}


long Proc12_SspirLogonUser( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ struct Struct_984_t *arg_2,
    /* [in] */ short arg_3,
    /* [in] */ long arg_4,
    /* [in] */ struct Struct_282_t *arg_5,
    /* [in] */ struct Struct_1016_t *arg_6,
    /* [unique][in] */ struct Struct_1144_t *arg_7,
    /* [in] */ long arg_8,
    /* [size_is][unique][in] */ unsigned char *arg_9,
    /* [out] */ long *arg_10,
    /* [out] */ hyper *arg_11,
    /* [out] */ long *arg_12,
    /* [out][in] */ struct Struct_248_t *arg_13,
    /* [out] */ hyper *arg_14,
    /* [out] */ struct Struct_1206_t *arg_15)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  12,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4,
                  arg_5,
                  arg_6,
                  arg_7,
                  arg_8,
                  arg_9,
                  arg_10,
                  arg_11,
                  arg_12,
                  arg_13,
                  arg_14,
                  arg_15);
    return ( long  )_RetVal.Simple;
    
}


long Proc13_SspirLookupAccountSid( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ struct Struct_1072_t *arg_2,
    /* [out] */ struct Struct_222_t *arg_3,
    /* [out] */ struct Struct_222_t *arg_4,
    /* [ref][out] */ short *arg_5)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  13,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4,
                  arg_5);
    return ( long  )_RetVal.Simple;
    
}


long Proc14_SspirGetUserName( 
    /* [context_handle][in] */ void *arg_0,
    /* [in] */ struct Struct_172_t *arg_1,
    /* [in] */ long arg_2,
    /* [out] */ struct Struct_222_t *arg_3,
    /* [out] */ long *arg_4)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  14,
                  0,
                  arg_0,
                  arg_1,
                  arg_2,
                  arg_3,
                  arg_4);
    return ( long  )_RetVal.Simple;
    
}


long Proc15_SspirGetInprocDispatchTable( 
    /* [context_handle][in] */ void *arg_0,
    /* [out] */ unsigned __int3264 *arg_1)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  15,
                  0,
                  arg_0,
                  arg_1);
    return ( long  )_RetVal.Simple;
    
}


#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

static const sspi_MIDL_PROC_FORMAT_STRING sspi__MIDL_ProcFormatString =
    {
        0,
        {

	/* Procedure Proc0_SspirConnectRpc */

			0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 10 */	NdrFcShort( 0x8 ),	/* 8 */
/* 12 */	NdrFcShort( 0x78 ),	/* 120 */
/* 14 */	0x46,		/* Oi2 Flags:  clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 16 */	0xa,		/* 10 */
			0x41,		/* Ext Flags:  new corr desc, has range on conformance */
/* 18 */	NdrFcShort( 0x0 ),	/* 0 */
/* 20 */	NdrFcShort( 0x0 ),	/* 0 */
/* 22 */	NdrFcShort( 0x0 ),	/* 0 */
/* 24 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_1 */

/* 26 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 28 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 30 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter arg_2 */

/* 32 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 34 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 36 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_3 */

/* 38 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 40 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 42 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_4 */

/* 44 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 46 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 48 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_5 */

/* 50 */	NdrFcShort( 0x110 ),	/* Flags:  out, simple ref, */
/* 52 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 54 */	NdrFcShort( 0xe ),	/* Type Offset=14 */

	/* Return value */

/* 56 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 58 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 60 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc1_SspirDisconnectRpc */

/* 62 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 64 */	NdrFcLong( 0x0 ),	/* 0 */
/* 68 */	NdrFcShort( 0x1 ),	/* 1 */
/* 70 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 72 */	0x30,		/* FC_BIND_CONTEXT */
			0xe0,		/* Ctxt flags:  via ptr, in, out, */
/* 74 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 76 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 78 */	NdrFcShort( 0x38 ),	/* 56 */
/* 80 */	NdrFcShort( 0x40 ),	/* 64 */
/* 82 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x2,		/* 2 */
/* 84 */	0xa,		/* 10 */
			0x41,		/* Ext Flags:  new corr desc, has range on conformance */
/* 86 */	NdrFcShort( 0x0 ),	/* 0 */
/* 88 */	NdrFcShort( 0x0 ),	/* 0 */
/* 90 */	NdrFcShort( 0x0 ),	/* 0 */
/* 92 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 94 */	NdrFcShort( 0x118 ),	/* Flags:  in, out, simple ref, */
/* 96 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 98 */	NdrFcShort( 0x16 ),	/* Type Offset=22 */

	/* Return value */

/* 100 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 102 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 104 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc2_SspirDisconnectRpc */

/* 106 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 108 */	NdrFcLong( 0x0 ),	/* 0 */
/* 112 */	NdrFcShort( 0x2 ),	/* 2 */
/* 114 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 116 */	0x30,		/* FC_BIND_CONTEXT */
			0xe0,		/* Ctxt flags:  via ptr, in, out, */
/* 118 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 120 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 122 */	NdrFcShort( 0x38 ),	/* 56 */
/* 124 */	NdrFcShort( 0x40 ),	/* 64 */
/* 126 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x2,		/* 2 */
/* 128 */	0xa,		/* 10 */
			0x41,		/* Ext Flags:  new corr desc, has range on conformance */
/* 130 */	NdrFcShort( 0x0 ),	/* 0 */
/* 132 */	NdrFcShort( 0x0 ),	/* 0 */
/* 134 */	NdrFcShort( 0x0 ),	/* 0 */
/* 136 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 138 */	NdrFcShort( 0x118 ),	/* Flags:  in, out, simple ref, */
/* 140 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 142 */	NdrFcShort( 0x16 ),	/* Type Offset=22 */

	/* Return value */

/* 144 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 146 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 148 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc3_SspirCallRpc */

/* 150 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 152 */	NdrFcLong( 0x0 ),	/* 0 */
/* 156 */	NdrFcShort( 0x3 ),	/* 3 */
/* 158 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 160 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 162 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 164 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 166 */	NdrFcShort( 0x2c ),	/* 44 */
/* 168 */	NdrFcShort( 0x24 ),	/* 36 */
/* 170 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x7,		/* 7 */
/* 172 */	0xa,		/* 10 */
			0x47,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, has range on conformance */
/* 174 */	NdrFcShort( 0x1 ),	/* 1 */
/* 176 */	NdrFcShort( 0x1 ),	/* 1 */
/* 178 */	NdrFcShort( 0x0 ),	/* 0 */
/* 180 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 182 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 184 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 186 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 188 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 190 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 192 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_2 */

/* 194 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 196 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 198 */	NdrFcShort( 0x22 ),	/* Type Offset=34 */

	/* Parameter arg_3 */

/* 200 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 202 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 204 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_4 */

/* 206 */	NdrFcShort( 0x2013 ),	/* Flags:  must size, must free, out, srv alloc size=8 */
/* 208 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 210 */	NdrFcShort( 0x38 ),	/* Type Offset=56 */

	/* Parameter arg_5 */

/* 212 */	NdrFcShort( 0xc113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=48 */
/* 214 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 216 */	NdrFcShort( 0x80 ),	/* Type Offset=128 */

	/* Return value */

/* 218 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 220 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 222 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc4_SspirAcquireCredentialsHandle */

/* 224 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 226 */	NdrFcLong( 0x0 ),	/* 0 */
/* 230 */	NdrFcShort( 0x4 ),	/* 4 */
/* 232 */	NdrFcShort( 0x78 ),	/* X64 Stack size/offset = 120 */
/* 234 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 236 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 238 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 240 */	NdrFcShort( 0xb4 ),	/* 180 */
/* 242 */	NdrFcShort( 0x68 ),	/* 104 */
/* 244 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0xf,		/* 15 */
/* 246 */	0xa,		/* 10 */
			0x47,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, has range on conformance */
/* 248 */	NdrFcShort( 0x1 ),	/* 1 */
/* 250 */	NdrFcShort( 0x1 ),	/* 1 */
/* 252 */	NdrFcShort( 0x0 ),	/* 0 */
/* 254 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 256 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 258 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 260 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 262 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 264 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 266 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 268 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 270 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 272 */	NdrFcShort( 0xa0 ),	/* Type Offset=160 */

	/* Parameter arg_3 */

/* 274 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 276 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 278 */	NdrFcShort( 0xca ),	/* Type Offset=202 */

	/* Parameter arg_4 */

/* 280 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 282 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 284 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_5 */

/* 286 */	NdrFcShort( 0xa ),	/* Flags:  must free, in, */
/* 288 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 290 */	NdrFcShort( 0xe0 ),	/* Type Offset=224 */

	/* Parameter arg_6 */

/* 292 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 294 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 296 */	NdrFcShort( 0xf0 ),	/* Type Offset=240 */

	/* Parameter arg_7 */

/* 298 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 300 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 302 */	0xb,		/* FC_HYPER */
			0x0,		/* 0 */

	/* Parameter arg_8 */

/* 304 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 306 */	NdrFcShort( 0x40 ),	/* X64 Stack size/offset = 64 */
/* 308 */	0xb,		/* FC_HYPER */
			0x0,		/* 0 */

	/* Parameter arg_9 */

/* 310 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 312 */	NdrFcShort( 0x48 ),	/* X64 Stack size/offset = 72 */
/* 314 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_10 */

/* 316 */	NdrFcShort( 0x4112 ),	/* Flags:  must free, out, simple ref, srv alloc size=16 */
/* 318 */	NdrFcShort( 0x50 ),	/* X64 Stack size/offset = 80 */
/* 320 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_11 */

/* 322 */	NdrFcShort( 0x2112 ),	/* Flags:  must free, out, simple ref, srv alloc size=8 */
/* 324 */	NdrFcShort( 0x58 ),	/* X64 Stack size/offset = 88 */
/* 326 */	NdrFcShort( 0x10a ),	/* Type Offset=266 */

	/* Parameter arg_12 */

/* 328 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 330 */	NdrFcShort( 0x60 ),	/* X64 Stack size/offset = 96 */
/* 332 */	NdrFcShort( 0x80 ),	/* Type Offset=128 */

	/* Parameter arg_13 */

/* 334 */	NdrFcShort( 0xc113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=48 */
/* 336 */	NdrFcShort( 0x68 ),	/* X64 Stack size/offset = 104 */
/* 338 */	NdrFcShort( 0x80 ),	/* Type Offset=128 */

	/* Return value */

/* 340 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 342 */	NdrFcShort( 0x70 ),	/* X64 Stack size/offset = 112 */
/* 344 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc5_SspirFreeCredentialsHandle */

/* 346 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 348 */	NdrFcLong( 0x0 ),	/* 0 */
/* 352 */	NdrFcShort( 0x5 ),	/* 5 */
/* 354 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 356 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 358 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 360 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 362 */	NdrFcShort( 0x8c ),	/* 140 */
/* 364 */	NdrFcShort( 0x8 ),	/* 8 */
/* 366 */	0x45,		/* Oi2 Flags:  srv must size, has return, has ext, */
			0x5,		/* 5 */
/* 368 */	0xa,		/* 10 */
			0x43,		/* Ext Flags:  new corr desc, clt corr check, has range on conformance */
/* 370 */	NdrFcShort( 0x1 ),	/* 1 */
/* 372 */	NdrFcShort( 0x0 ),	/* 0 */
/* 374 */	NdrFcShort( 0x0 ),	/* 0 */
/* 376 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 378 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 380 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 382 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 384 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 386 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 388 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 390 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 392 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 394 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_3 */

/* 396 */	NdrFcShort( 0xc113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=48 */
/* 398 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 400 */	NdrFcShort( 0x80 ),	/* Type Offset=128 */

	/* Return value */

/* 402 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 404 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 406 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc6_SspirProcessSecurityContext */

/* 408 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 410 */	NdrFcLong( 0x0 ),	/* 0 */
/* 414 */	NdrFcShort( 0x6 ),	/* 6 */
/* 416 */	NdrFcShort( 0xb0 ),	/* X64 Stack size/offset = 176 */
/* 418 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 420 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 422 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 424 */	NdrFcShort( 0xec ),	/* 236 */
/* 426 */	NdrFcShort( 0xbc ),	/* 188 */
/* 428 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x16,		/* 22 */
/* 430 */	0xa,		/* 10 */
			0x47,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, has range on conformance */
/* 432 */	NdrFcShort( 0x1 ),	/* 1 */
/* 434 */	NdrFcShort( 0x1 ),	/* 1 */
/* 436 */	NdrFcShort( 0x0 ),	/* 0 */
/* 438 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 440 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 442 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 444 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 446 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 448 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 450 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 452 */	NdrFcShort( 0x158 ),	/* Flags:  in, out, base type, simple ref, */
/* 454 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 456 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_3 */

/* 458 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 460 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 462 */	NdrFcShort( 0xa0 ),	/* Type Offset=160 */

	/* Parameter arg_4 */

/* 464 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 466 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 468 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_5 */

/* 470 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 472 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 474 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_6 */

/* 476 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 478 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 480 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_7 */

/* 482 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 484 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 486 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_8 */

/* 488 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 490 */	NdrFcShort( 0x40 ),	/* X64 Stack size/offset = 64 */
/* 492 */	NdrFcShort( 0x118 ),	/* Type Offset=280 */

	/* Parameter arg_9 */

/* 494 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 496 */	NdrFcShort( 0x48 ),	/* X64 Stack size/offset = 72 */
/* 498 */	NdrFcShort( 0x132 ),	/* Type Offset=306 */

	/* Parameter arg_10 */

/* 500 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 502 */	NdrFcShort( 0x50 ),	/* X64 Stack size/offset = 80 */
/* 504 */	NdrFcShort( 0x164 ),	/* Type Offset=356 */

	/* Parameter arg_11 */

/* 506 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 508 */	NdrFcShort( 0x58 ),	/* X64 Stack size/offset = 88 */
/* 510 */	NdrFcShort( 0x1a2 ),	/* Type Offset=418 */

	/* Parameter arg_12 */

/* 512 */	NdrFcShort( 0x4113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=16 */
/* 514 */	NdrFcShort( 0x60 ),	/* X64 Stack size/offset = 96 */
/* 516 */	NdrFcShort( 0x164 ),	/* Type Offset=356 */

	/* Parameter arg_13 */

/* 518 */	NdrFcShort( 0x2013 ),	/* Flags:  must size, must free, out, srv alloc size=8 */
/* 520 */	NdrFcShort( 0x68 ),	/* X64 Stack size/offset = 104 */
/* 522 */	NdrFcShort( 0x1b6 ),	/* Type Offset=438 */

	/* Parameter arg_14 */

/* 524 */	NdrFcShort( 0x4113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=16 */
/* 526 */	NdrFcShort( 0x70 ),	/* X64 Stack size/offset = 112 */
/* 528 */	NdrFcShort( 0x70 ),	/* Type Offset=112 */

	/* Parameter arg_15 */

/* 530 */	NdrFcShort( 0x4112 ),	/* Flags:  must free, out, simple ref, srv alloc size=16 */
/* 532 */	NdrFcShort( 0x78 ),	/* X64 Stack size/offset = 120 */
/* 534 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_16 */

/* 536 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 538 */	NdrFcShort( 0x80 ),	/* X64 Stack size/offset = 128 */
/* 540 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_17 */

/* 542 */	NdrFcShort( 0x2112 ),	/* Flags:  must free, out, simple ref, srv alloc size=8 */
/* 544 */	NdrFcShort( 0x88 ),	/* X64 Stack size/offset = 136 */
/* 546 */	NdrFcShort( 0x10a ),	/* Type Offset=266 */

	/* Parameter arg_18 */

/* 548 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 550 */	NdrFcShort( 0x90 ),	/* X64 Stack size/offset = 144 */
/* 552 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_19 */

/* 554 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 556 */	NdrFcShort( 0x98 ),	/* X64 Stack size/offset = 152 */
/* 558 */	NdrFcShort( 0x80 ),	/* Type Offset=128 */

	/* Parameter arg_20 */

/* 560 */	NdrFcShort( 0xc113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=48 */
/* 562 */	NdrFcShort( 0xa0 ),	/* X64 Stack size/offset = 160 */
/* 564 */	NdrFcShort( 0x80 ),	/* Type Offset=128 */

	/* Return value */

/* 566 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 568 */	NdrFcShort( 0xa8 ),	/* X64 Stack size/offset = 168 */
/* 570 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc7_SspirDeleteSecurityContext */

/* 572 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 574 */	NdrFcLong( 0x0 ),	/* 0 */
/* 578 */	NdrFcShort( 0x7 ),	/* 7 */
/* 580 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 582 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 584 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 586 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 588 */	NdrFcShort( 0x8c ),	/* 140 */
/* 590 */	NdrFcShort( 0x8 ),	/* 8 */
/* 592 */	0x45,		/* Oi2 Flags:  srv must size, has return, has ext, */
			0x5,		/* 5 */
/* 594 */	0xa,		/* 10 */
			0x43,		/* Ext Flags:  new corr desc, clt corr check, has range on conformance */
/* 596 */	NdrFcShort( 0x1 ),	/* 1 */
/* 598 */	NdrFcShort( 0x0 ),	/* 0 */
/* 600 */	NdrFcShort( 0x0 ),	/* 0 */
/* 602 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 604 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 606 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 608 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 610 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 612 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 614 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 616 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 618 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 620 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_3 */

/* 622 */	NdrFcShort( 0xc113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=48 */
/* 624 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 626 */	NdrFcShort( 0x80 ),	/* Type Offset=128 */

	/* Return value */

/* 628 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 630 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 632 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc8_SspirSslQueryCredentialsAttributes */

/* 634 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 636 */	NdrFcLong( 0x0 ),	/* 0 */
/* 640 */	NdrFcShort( 0x8 ),	/* 8 */
/* 642 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 644 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 646 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 648 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 650 */	NdrFcShort( 0x94 ),	/* 148 */
/* 652 */	NdrFcShort( 0x8 ),	/* 8 */
/* 654 */	0x45,		/* Oi2 Flags:  srv must size, has return, has ext, */
			0x6,		/* 6 */
/* 656 */	0xa,		/* 10 */
			0x43,		/* Ext Flags:  new corr desc, clt corr check, has range on conformance */
/* 658 */	NdrFcShort( 0x1 ),	/* 1 */
/* 660 */	NdrFcShort( 0x0 ),	/* 0 */
/* 662 */	NdrFcShort( 0x0 ),	/* 0 */
/* 664 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 666 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 668 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 670 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 672 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 674 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 676 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 678 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 680 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 682 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_3 */

/* 684 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 686 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 688 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_4 */

/* 690 */	NdrFcShort( 0x2113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=8 */
/* 692 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 694 */	NdrFcShort( 0x1c6 ),	/* Type Offset=454 */

	/* Return value */

/* 696 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 698 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 700 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc9_SspirNegQueryContextAttributes */

/* 702 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 704 */	NdrFcLong( 0x0 ),	/* 0 */
/* 708 */	NdrFcShort( 0x9 ),	/* 9 */
/* 710 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 712 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 714 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 716 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 718 */	NdrFcShort( 0x94 ),	/* 148 */
/* 720 */	NdrFcShort( 0x8 ),	/* 8 */
/* 722 */	0x45,		/* Oi2 Flags:  srv must size, has return, has ext, */
			0x6,		/* 6 */
/* 724 */	0xa,		/* 10 */
			0x43,		/* Ext Flags:  new corr desc, clt corr check, has range on conformance */
/* 726 */	NdrFcShort( 0x1 ),	/* 1 */
/* 728 */	NdrFcShort( 0x0 ),	/* 0 */
/* 730 */	NdrFcShort( 0x0 ),	/* 0 */
/* 732 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 734 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 736 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 738 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 740 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 742 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 744 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 746 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 748 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 750 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_3 */

/* 752 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 754 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 756 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_4 */

/* 758 */	NdrFcShort( 0x2113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=8 */
/* 760 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 762 */	NdrFcShort( 0x22c ),	/* Type Offset=556 */

	/* Return value */

/* 764 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 766 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 768 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc10_SspirSslSetCredentialsAttributes */

/* 770 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 772 */	NdrFcLong( 0x0 ),	/* 0 */
/* 776 */	NdrFcShort( 0xa ),	/* 10 */
/* 778 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 780 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 782 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 784 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 786 */	NdrFcShort( 0x8c ),	/* 140 */
/* 788 */	NdrFcShort( 0x8 ),	/* 8 */
/* 790 */	0x46,		/* Oi2 Flags:  clt must size, has return, has ext, */
			0x5,		/* 5 */
/* 792 */	0xa,		/* 10 */
			0x41,		/* Ext Flags:  new corr desc, has range on conformance */
/* 794 */	NdrFcShort( 0x0 ),	/* 0 */
/* 796 */	NdrFcShort( 0x0 ),	/* 0 */
/* 798 */	NdrFcShort( 0x0 ),	/* 0 */
/* 800 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 802 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 804 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 806 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 808 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 810 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 812 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 814 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 816 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 818 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_3 */

/* 820 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 822 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 824 */	NdrFcShort( 0x2be ),	/* Type Offset=702 */

	/* Return value */

/* 826 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 828 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 830 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc11_SspirApplyControlToken */

/* 832 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 834 */	NdrFcLong( 0x0 ),	/* 0 */
/* 838 */	NdrFcShort( 0xb ),	/* 11 */
/* 840 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 842 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 844 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 846 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 848 */	NdrFcShort( 0x8c ),	/* 140 */
/* 850 */	NdrFcShort( 0x8 ),	/* 8 */
/* 852 */	0x46,		/* Oi2 Flags:  clt must size, has return, has ext, */
			0x5,		/* 5 */
/* 854 */	0xa,		/* 10 */
			0x45,		/* Ext Flags:  new corr desc, srv corr check, has range on conformance */
/* 856 */	NdrFcShort( 0x0 ),	/* 0 */
/* 858 */	NdrFcShort( 0x1 ),	/* 1 */
/* 860 */	NdrFcShort( 0x0 ),	/* 0 */
/* 862 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 864 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 866 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 868 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 870 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 872 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 874 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 876 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 878 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 880 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_3 */

/* 882 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 884 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 886 */	NdrFcShort( 0x164 ),	/* Type Offset=356 */

	/* Return value */

/* 888 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 890 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 892 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc12_SspirLogonUser */

/* 894 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 896 */	NdrFcLong( 0x0 ),	/* 0 */
/* 900 */	NdrFcShort( 0xc ),	/* 12 */
/* 902 */	NdrFcShort( 0x88 ),	/* X64 Stack size/offset = 136 */
/* 904 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 906 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 908 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 910 */	NdrFcShort( 0xee ),	/* 238 */
/* 912 */	NdrFcShort( 0x118 ),	/* 280 */
/* 914 */	0x46,		/* Oi2 Flags:  clt must size, has return, has ext, */
			0x11,		/* 17 */
/* 916 */	0xa,		/* 10 */
			0x45,		/* Ext Flags:  new corr desc, srv corr check, has range on conformance */
/* 918 */	NdrFcShort( 0x0 ),	/* 0 */
/* 920 */	NdrFcShort( 0x1 ),	/* 1 */
/* 922 */	NdrFcShort( 0x0 ),	/* 0 */
/* 924 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 926 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 928 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 930 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 932 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 934 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 936 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 938 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 940 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 942 */	NdrFcShort( 0x306 ),	/* Type Offset=774 */

	/* Parameter arg_3 */

/* 944 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 946 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 948 */	0x6,		/* FC_SHORT */
			0x0,		/* 0 */

	/* Parameter arg_4 */

/* 950 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 952 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 954 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_5 */

/* 956 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 958 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 960 */	NdrFcShort( 0xf0 ),	/* Type Offset=240 */

	/* Parameter arg_6 */

/* 962 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 964 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 966 */	NdrFcShort( 0x322 ),	/* Type Offset=802 */

	/* Parameter arg_7 */

/* 968 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 970 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 972 */	NdrFcShort( 0x330 ),	/* Type Offset=816 */

	/* Parameter arg_8 */

/* 974 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 976 */	NdrFcShort( 0x40 ),	/* X64 Stack size/offset = 64 */
/* 978 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_9 */

/* 980 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 982 */	NdrFcShort( 0x48 ),	/* X64 Stack size/offset = 72 */
/* 984 */	NdrFcShort( 0x118 ),	/* Type Offset=280 */

	/* Parameter arg_10 */

/* 986 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 988 */	NdrFcShort( 0x50 ),	/* X64 Stack size/offset = 80 */
/* 990 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_11 */

/* 992 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 994 */	NdrFcShort( 0x58 ),	/* X64 Stack size/offset = 88 */
/* 996 */	0xb,		/* FC_HYPER */
			0x0,		/* 0 */

	/* Parameter arg_12 */

/* 998 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 1000 */	NdrFcShort( 0x60 ),	/* X64 Stack size/offset = 96 */
/* 1002 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_13 */

/* 1004 */	NdrFcShort( 0x11a ),	/* Flags:  must free, in, out, simple ref, */
/* 1006 */	NdrFcShort( 0x68 ),	/* X64 Stack size/offset = 104 */
/* 1008 */	NdrFcShort( 0xe4 ),	/* Type Offset=228 */

	/* Parameter arg_14 */

/* 1010 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 1012 */	NdrFcShort( 0x70 ),	/* X64 Stack size/offset = 112 */
/* 1014 */	0xb,		/* FC_HYPER */
			0x0,		/* 0 */

	/* Parameter arg_15 */

/* 1016 */	NdrFcShort( 0xc112 ),	/* Flags:  must free, out, simple ref, srv alloc size=48 */
/* 1018 */	NdrFcShort( 0x78 ),	/* X64 Stack size/offset = 120 */
/* 1020 */	NdrFcShort( 0x3ba ),	/* Type Offset=954 */

	/* Return value */

/* 1022 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1024 */	NdrFcShort( 0x80 ),	/* X64 Stack size/offset = 128 */
/* 1026 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc13_SspirLookupAccountSid */

/* 1028 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1030 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1034 */	NdrFcShort( 0xd ),	/* 13 */
/* 1036 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 1038 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 1040 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1042 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 1044 */	NdrFcShort( 0x58 ),	/* 88 */
/* 1046 */	NdrFcShort( 0x22 ),	/* 34 */
/* 1048 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x7,		/* 7 */
/* 1050 */	0xa,		/* 10 */
			0x47,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, has range on conformance */
/* 1052 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1054 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1056 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1058 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 1060 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 1062 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1064 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 1066 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 1068 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1070 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 1072 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 1074 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1076 */	NdrFcShort( 0x35a ),	/* Type Offset=858 */

	/* Parameter arg_3 */

/* 1078 */	NdrFcShort( 0x4113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=16 */
/* 1080 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 1082 */	NdrFcShort( 0xca ),	/* Type Offset=202 */

	/* Parameter arg_4 */

/* 1084 */	NdrFcShort( 0x4113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=16 */
/* 1086 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 1088 */	NdrFcShort( 0xca ),	/* Type Offset=202 */

	/* Parameter arg_5 */

/* 1090 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 1092 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 1094 */	0x6,		/* FC_SHORT */
			0x0,		/* 0 */

	/* Return value */

/* 1096 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1098 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 1100 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc14_SspirGetUserName */

/* 1102 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1104 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1108 */	NdrFcShort( 0xe ),	/* 14 */
/* 1110 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 1112 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 1114 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1116 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 1118 */	NdrFcShort( 0x60 ),	/* 96 */
/* 1120 */	NdrFcShort( 0x24 ),	/* 36 */
/* 1122 */	0x45,		/* Oi2 Flags:  srv must size, has return, has ext, */
			0x6,		/* 6 */
/* 1124 */	0xa,		/* 10 */
			0x43,		/* Ext Flags:  new corr desc, clt corr check, has range on conformance */
/* 1126 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1128 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1130 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1132 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 1134 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 1136 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1138 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 1140 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 1142 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1144 */	NdrFcShort( 0x98 ),	/* Type Offset=152 */

	/* Parameter arg_2 */

/* 1146 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 1148 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1150 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter arg_3 */

/* 1152 */	NdrFcShort( 0x4113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=16 */
/* 1154 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 1156 */	NdrFcShort( 0xca ),	/* Type Offset=202 */

	/* Parameter arg_4 */

/* 1158 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 1160 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 1162 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Return value */

/* 1164 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1166 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 1168 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure Proc15_SspirGetInprocDispatchTable */

/* 1170 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1172 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1176 */	NdrFcShort( 0xf ),	/* 15 */
/* 1178 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 1180 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 1182 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1184 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 1186 */	NdrFcShort( 0x24 ),	/* 36 */
/* 1188 */	NdrFcShort( 0x24 ),	/* 36 */
/* 1190 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x3,		/* 3 */
/* 1192 */	0xa,		/* 10 */
			0x41,		/* Ext Flags:  new corr desc, has range on conformance */
/* 1194 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1196 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1198 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1200 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_0 */

/* 1202 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 1204 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 1206 */	NdrFcShort( 0x1a ),	/* Type Offset=26 */

	/* Parameter arg_1 */

/* 1208 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 1210 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1212 */	0xb9,		/* FC_UINT3264 */
			0x0,		/* 0 */

	/* Return value */

/* 1214 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1216 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 1218 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const sspi_MIDL_TYPE_FORMAT_STRING sspi__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/*  4 */	
			0x22,		/* FC_C_CSTRING */
			0x5c,		/* FC_PAD */
/*  6 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/*  8 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */
/* 10 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 12 */	NdrFcShort( 0x2 ),	/* Offset= 2 (14) */
/* 14 */	0x30,		/* FC_BIND_CONTEXT */
			0xa0,		/* Ctxt flags:  via ptr, out, */
/* 16 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 18 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 20 */	NdrFcShort( 0x2 ),	/* Offset= 2 (22) */
/* 22 */	0x30,		/* FC_BIND_CONTEXT */
			0xe1,		/* Ctxt flags:  via ptr, in, out, can't be null */
/* 24 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 26 */	0x30,		/* FC_BIND_CONTEXT */
			0x41,		/* Ctxt flags:  in, can't be null */
/* 28 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 30 */	
			0x11, 0x0,	/* FC_RP */
/* 32 */	NdrFcShort( 0x2 ),	/* Offset= 2 (34) */
/* 34 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 36 */	NdrFcShort( 0x1 ),	/* 1 */
/* 38 */	0x28,		/* Corr desc:  parameter, FC_LONG */
			0x0,		/*  */
/* 40 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 42 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 44 */	0x0 , 
			0x0,		/* 0 */
/* 46 */	NdrFcLong( 0x0 ),	/* 0 */
/* 50 */	NdrFcLong( 0x0 ),	/* 0 */
/* 54 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 56 */	
			0x11, 0x14,	/* FC_RP [alloced_on_stack] [pointer_deref] */
/* 58 */	NdrFcShort( 0x2 ),	/* Offset= 2 (60) */
/* 60 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 62 */	NdrFcShort( 0x2 ),	/* Offset= 2 (64) */
/* 64 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 66 */	NdrFcShort( 0x1 ),	/* 1 */
/* 68 */	0x28,		/* Corr desc:  parameter, FC_LONG */
			0x54,		/* FC_DEREFERENCE */
/* 70 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 72 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 74 */	0x0 , 
			0x0,		/* 0 */
/* 76 */	NdrFcLong( 0x0 ),	/* 0 */
/* 80 */	NdrFcLong( 0x0 ),	/* 0 */
/* 84 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 86 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 88 */	NdrFcShort( 0x28 ),	/* Offset= 40 (128) */
/* 90 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 92 */	NdrFcShort( 0x1 ),	/* 1 */
/* 94 */	0x18,		/* Corr desc:  field pointer, FC_LONG */
			0x0,		/*  */
/* 96 */	NdrFcShort( 0x0 ),	/* 0 */
/* 98 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 100 */	0x0 , 
			0x0,		/* 0 */
/* 102 */	NdrFcLong( 0x0 ),	/* 0 */
/* 106 */	NdrFcLong( 0x0 ),	/* 0 */
/* 110 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 112 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 114 */	NdrFcShort( 0x10 ),	/* 16 */
/* 116 */	NdrFcShort( 0x0 ),	/* 0 */
/* 118 */	NdrFcShort( 0x6 ),	/* Offset= 6 (124) */
/* 120 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 122 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 124 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 126 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (90) */
/* 128 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 130 */	NdrFcShort( 0x30 ),	/* 48 */
/* 132 */	NdrFcShort( 0x0 ),	/* 0 */
/* 134 */	NdrFcShort( 0x0 ),	/* Offset= 0 (134) */
/* 136 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 138 */	0xb9,		/* FC_UINT3264 */
			0xb9,		/* FC_UINT3264 */
/* 140 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 142 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (112) */
/* 144 */	0x2,		/* FC_CHAR */
			0x43,		/* FC_STRUCTPAD7 */
/* 146 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 148 */	
			0x11, 0x0,	/* FC_RP */
/* 150 */	NdrFcShort( 0x2 ),	/* Offset= 2 (152) */
/* 152 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 154 */	NdrFcShort( 0x10 ),	/* 16 */
/* 156 */	0xb,		/* FC_HYPER */
			0xb,		/* FC_HYPER */
/* 158 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 160 */	
			0x12, 0x0,	/* FC_UP */
/* 162 */	NdrFcShort( 0x28 ),	/* Offset= 40 (202) */
/* 164 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 166 */	NdrFcShort( 0x2 ),	/* 2 */
/* 168 */	0x16,		/* Corr desc:  field pointer, FC_SHORT */
			0x55,		/* FC_DIV_2 */
/* 170 */	NdrFcShort( 0x2 ),	/* 2 */
/* 172 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 174 */	0x0 , 
			0x0,		/* 0 */
/* 176 */	NdrFcLong( 0x0 ),	/* 0 */
/* 180 */	NdrFcLong( 0x0 ),	/* 0 */
/* 184 */	0x16,		/* Corr desc:  field pointer, FC_SHORT */
			0x55,		/* FC_DIV_2 */
/* 186 */	NdrFcShort( 0x0 ),	/* 0 */
/* 188 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 190 */	0x0 , 
			0x0,		/* 0 */
/* 192 */	NdrFcLong( 0x0 ),	/* 0 */
/* 196 */	NdrFcLong( 0x0 ),	/* 0 */
/* 200 */	0x6,		/* FC_SHORT */
			0x5b,		/* FC_END */
/* 202 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 204 */	NdrFcShort( 0x10 ),	/* 16 */
/* 206 */	NdrFcShort( 0x0 ),	/* 0 */
/* 208 */	NdrFcShort( 0x8 ),	/* Offset= 8 (216) */
/* 210 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 212 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 214 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 216 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 218 */	NdrFcShort( 0xffca ),	/* Offset= -54 (164) */
/* 220 */	
			0x11, 0x0,	/* FC_RP */
/* 222 */	NdrFcShort( 0xffec ),	/* Offset= -20 (202) */
/* 224 */	
			0x12, 0x0,	/* FC_UP */
/* 226 */	NdrFcShort( 0x2 ),	/* Offset= 2 (228) */
/* 228 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 230 */	NdrFcShort( 0x8 ),	/* 8 */
/* 232 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 234 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 236 */	
			0x11, 0x0,	/* FC_RP */
/* 238 */	NdrFcShort( 0x2 ),	/* Offset= 2 (240) */
/* 240 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 242 */	NdrFcShort( 0x18 ),	/* 24 */
/* 244 */	NdrFcShort( 0x0 ),	/* 0 */
/* 246 */	NdrFcShort( 0x8 ),	/* Offset= 8 (254) */
/* 248 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 250 */	0xb,		/* FC_HYPER */
			0x36,		/* FC_POINTER */
/* 252 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 254 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 256 */	NdrFcShort( 0xff5a ),	/* Offset= -166 (90) */
/* 258 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 260 */	NdrFcShort( 0xff94 ),	/* Offset= -108 (152) */
/* 262 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 264 */	NdrFcShort( 0x2 ),	/* Offset= 2 (266) */
/* 266 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 268 */	NdrFcShort( 0x8 ),	/* 8 */
/* 270 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 272 */	
			0x11, 0x0,	/* FC_RP */
/* 274 */	NdrFcShort( 0xff6e ),	/* Offset= -146 (128) */
/* 276 */	
			0x11, 0x8,	/* FC_RP [simple_pointer] */
/* 278 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */
/* 280 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 282 */	NdrFcShort( 0x2 ),	/* Offset= 2 (284) */
/* 284 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 286 */	NdrFcShort( 0x1 ),	/* 1 */
/* 288 */	0x40,		/* Corr desc:  constant, val=32 */
			0x0,		/* 0 */
/* 290 */	NdrFcShort( 0x20 ),	/* 32 */
/* 292 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 294 */	0x0 , 
			0x0,		/* 0 */
/* 296 */	NdrFcLong( 0x0 ),	/* 0 */
/* 300 */	NdrFcLong( 0x0 ),	/* 0 */
/* 304 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 306 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 308 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 310 */	
			0x11, 0x0,	/* FC_RP */
/* 312 */	NdrFcShort( 0x2c ),	/* Offset= 44 (356) */
/* 314 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 316 */	NdrFcShort( 0x0 ),	/* 0 */
/* 318 */	0x18,		/* Corr desc:  field pointer, FC_LONG */
			0x0,		/*  */
/* 320 */	NdrFcShort( 0x4 ),	/* 4 */
/* 322 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 324 */	0x0 , 
			0x0,		/* 0 */
/* 326 */	NdrFcLong( 0x0 ),	/* 0 */
/* 330 */	NdrFcLong( 0x0 ),	/* 0 */
/* 334 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 338 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 340 */	0x0 , 
			0x0,		/* 0 */
/* 342 */	NdrFcLong( 0x0 ),	/* 0 */
/* 346 */	NdrFcLong( 0x0 ),	/* 0 */
/* 350 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 352 */	NdrFcShort( 0xff10 ),	/* Offset= -240 (112) */
/* 354 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 356 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 358 */	NdrFcShort( 0x10 ),	/* 16 */
/* 360 */	NdrFcShort( 0x0 ),	/* 0 */
/* 362 */	NdrFcShort( 0x6 ),	/* Offset= 6 (368) */
/* 364 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 366 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 368 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 370 */	NdrFcShort( 0xffc8 ),	/* Offset= -56 (314) */
/* 372 */	
			0x11, 0x0,	/* FC_RP */
/* 374 */	NdrFcShort( 0x2c ),	/* Offset= 44 (418) */
/* 376 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 378 */	NdrFcShort( 0x0 ),	/* 0 */
/* 380 */	0x18,		/* Corr desc:  field pointer, FC_LONG */
			0x0,		/*  */
/* 382 */	NdrFcShort( 0x4 ),	/* 4 */
/* 384 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 386 */	0x0 , 
			0x0,		/* 0 */
/* 388 */	NdrFcLong( 0x0 ),	/* 0 */
/* 392 */	NdrFcLong( 0x0 ),	/* 0 */
/* 396 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 400 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 402 */	0x0 , 
			0x0,		/* 0 */
/* 404 */	NdrFcLong( 0x0 ),	/* 0 */
/* 408 */	NdrFcLong( 0x0 ),	/* 0 */
/* 412 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 414 */	NdrFcShort( 0xff46 ),	/* Offset= -186 (228) */
/* 416 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 418 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 420 */	NdrFcShort( 0x10 ),	/* 16 */
/* 422 */	NdrFcShort( 0x0 ),	/* 0 */
/* 424 */	NdrFcShort( 0x6 ),	/* Offset= 6 (430) */
/* 426 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 428 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 430 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 432 */	NdrFcShort( 0xffc8 ),	/* Offset= -56 (376) */
/* 434 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 436 */	NdrFcShort( 0xffb0 ),	/* Offset= -80 (356) */
/* 438 */	
			0x11, 0x14,	/* FC_RP [alloced_on_stack] [pointer_deref] */
/* 440 */	NdrFcShort( 0x2 ),	/* Offset= 2 (442) */
/* 442 */	
			0x12, 0x0,	/* FC_UP */
/* 444 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (418) */
/* 446 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 448 */	NdrFcShort( 0xfeb0 ),	/* Offset= -336 (112) */
/* 450 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 452 */	NdrFcShort( 0x2 ),	/* Offset= 2 (454) */
/* 454 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x8,		/* FC_LONG */
/* 456 */	0x28,		/* Corr desc:  parameter, FC_LONG */
			0x0,		/*  */
/* 458 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 460 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 462 */	0x0 , 
			0x0,		/* 0 */
/* 464 */	NdrFcLong( 0x0 ),	/* 0 */
/* 468 */	NdrFcLong( 0x0 ),	/* 0 */
/* 472 */	NdrFcShort( 0x2 ),	/* Offset= 2 (474) */
/* 474 */	NdrFcShort( 0x8 ),	/* 8 */
/* 476 */	NdrFcShort( 0x4 ),	/* 4 */
/* 478 */	NdrFcLong( 0x1 ),	/* 1 */
/* 482 */	NdrFcShort( 0x16 ),	/* Offset= 22 (504) */
/* 484 */	NdrFcLong( 0x56 ),	/* 86 */
/* 488 */	NdrFcShort( 0x22 ),	/* Offset= 34 (522) */
/* 490 */	NdrFcLong( 0x57 ),	/* 87 */
/* 494 */	NdrFcShort( 0xfef2 ),	/* Offset= -270 (224) */
/* 496 */	NdrFcLong( 0x58 ),	/* 88 */
/* 500 */	NdrFcShort( 0x2a ),	/* Offset= 42 (542) */
/* 502 */	NdrFcShort( 0x0 ),	/* Offset= 0 (502) */
/* 504 */	
			0x12, 0x0,	/* FC_UP */
/* 506 */	NdrFcShort( 0x2 ),	/* Offset= 2 (508) */
/* 508 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 510 */	NdrFcShort( 0x8 ),	/* 8 */
/* 512 */	NdrFcShort( 0x0 ),	/* 0 */
/* 514 */	NdrFcShort( 0x4 ),	/* Offset= 4 (518) */
/* 516 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 518 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 520 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 522 */	
			0x12, 0x0,	/* FC_UP */
/* 524 */	NdrFcShort( 0x2 ),	/* Offset= 2 (526) */
/* 526 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 528 */	NdrFcShort( 0x10 ),	/* 16 */
/* 530 */	NdrFcShort( 0x0 ),	/* 0 */
/* 532 */	NdrFcShort( 0x6 ),	/* Offset= 6 (538) */
/* 534 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 536 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 538 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 540 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */
/* 542 */	
			0x12, 0x0,	/* FC_UP */
/* 544 */	NdrFcShort( 0x2 ),	/* Offset= 2 (546) */
/* 546 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 548 */	NdrFcShort( 0x4 ),	/* 4 */
/* 550 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 552 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 554 */	NdrFcShort( 0x2 ),	/* Offset= 2 (556) */
/* 556 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x8,		/* FC_LONG */
/* 558 */	0x28,		/* Corr desc:  parameter, FC_LONG */
			0x0,		/*  */
/* 560 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 562 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 564 */	0x0 , 
			0x0,		/* 0 */
/* 566 */	NdrFcLong( 0x0 ),	/* 0 */
/* 570 */	NdrFcLong( 0x0 ),	/* 0 */
/* 574 */	NdrFcShort( 0x2 ),	/* Offset= 2 (576) */
/* 576 */	NdrFcShort( 0x8 ),	/* 8 */
/* 578 */	NdrFcShort( 0x2 ),	/* 2 */
/* 580 */	NdrFcLong( 0x0 ),	/* 0 */
/* 584 */	NdrFcShort( 0xa ),	/* Offset= 10 (594) */
/* 586 */	NdrFcLong( 0xc ),	/* 12 */
/* 590 */	NdrFcShort( 0x12 ),	/* Offset= 18 (608) */
/* 592 */	NdrFcShort( 0x0 ),	/* Offset= 0 (592) */
/* 594 */	
			0x12, 0x0,	/* FC_UP */
/* 596 */	NdrFcShort( 0x2 ),	/* Offset= 2 (598) */
/* 598 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 600 */	NdrFcShort( 0x10 ),	/* 16 */
/* 602 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 604 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 606 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 608 */	
			0x12, 0x0,	/* FC_UP */
/* 610 */	NdrFcShort( 0x1a ),	/* Offset= 26 (636) */
/* 612 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 614 */	NdrFcShort( 0x20 ),	/* 32 */
/* 616 */	NdrFcShort( 0x0 ),	/* 0 */
/* 618 */	NdrFcShort( 0xa ),	/* Offset= 10 (628) */
/* 620 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 622 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 624 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 626 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 628 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 630 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 632 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 634 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 636 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 638 */	NdrFcShort( 0x10 ),	/* 16 */
/* 640 */	NdrFcShort( 0x0 ),	/* 0 */
/* 642 */	NdrFcShort( 0x6 ),	/* Offset= 6 (648) */
/* 644 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 646 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 648 */	
			0x12, 0x0,	/* FC_UP */
/* 650 */	NdrFcShort( 0xffda ),	/* Offset= -38 (612) */
/* 652 */	
			0x11, 0x0,	/* FC_RP */
/* 654 */	NdrFcShort( 0x30 ),	/* Offset= 48 (702) */
/* 656 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 658 */	NdrFcShort( 0x8 ),	/* 8 */
/* 660 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 662 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 664 */	NdrFcShort( 0x10 ),	/* 16 */
/* 666 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 668 */	0x6,		/* FC_SHORT */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 670 */	0x0,		/* 0 */
			NdrFcShort( 0xfff1 ),	/* Offset= -15 (656) */
			0x5b,		/* FC_END */
/* 674 */	0xb6,		/* FC_SUPPLEMENT */
			
			0x25,		/* FC_C_WSTRING */
/* 676 */	NdrFcShort( 0xa ),	/* Offset= 10 (686) */
/* 678 */	NdrFcLong( 0x0 ),	/* 0 */
/* 682 */	NdrFcLong( 0xffff ),	/* 65535 */
/* 686 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 688 */	0xb6,		/* FC_SUPPLEMENT */
			
			0x25,		/* FC_C_WSTRING */
/* 690 */	NdrFcShort( 0xa ),	/* Offset= 10 (700) */
/* 692 */	NdrFcLong( 0x0 ),	/* 0 */
/* 696 */	NdrFcLong( 0xffff ),	/* 65535 */
/* 700 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 702 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 704 */	NdrFcShort( 0x38 ),	/* 56 */
/* 706 */	NdrFcShort( 0x0 ),	/* 0 */
/* 708 */	NdrFcShort( 0x10 ),	/* Offset= 16 (724) */
/* 710 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 712 */	0x0,		/* 0 */
			NdrFcShort( 0xffcd ),	/* Offset= -51 (662) */
			0x8,		/* FC_LONG */
/* 716 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 718 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 720 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 722 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 724 */	
			0x12, 0x0,	/* FC_UP */
/* 726 */	NdrFcShort( 0xffcc ),	/* Offset= -52 (674) */
/* 728 */	
			0x12, 0x0,	/* FC_UP */
/* 730 */	NdrFcShort( 0xffd6 ),	/* Offset= -42 (688) */
/* 732 */	
			0x11, 0x0,	/* FC_RP */
/* 734 */	NdrFcShort( 0x28 ),	/* Offset= 40 (774) */
/* 736 */	
			0x1c,		/* FC_CVARRAY */
			0x0,		/* 0 */
/* 738 */	NdrFcShort( 0x1 ),	/* 1 */
/* 740 */	0x16,		/* Corr desc:  field pointer, FC_SHORT */
			0x0,		/*  */
/* 742 */	NdrFcShort( 0x2 ),	/* 2 */
/* 744 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 746 */	0x0 , 
			0x0,		/* 0 */
/* 748 */	NdrFcLong( 0x0 ),	/* 0 */
/* 752 */	NdrFcLong( 0x0 ),	/* 0 */
/* 756 */	0x16,		/* Corr desc:  field pointer, FC_SHORT */
			0x0,		/*  */
/* 758 */	NdrFcShort( 0x0 ),	/* 0 */
/* 760 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 762 */	0x0 , 
			0x0,		/* 0 */
/* 764 */	NdrFcLong( 0x0 ),	/* 0 */
/* 768 */	NdrFcLong( 0x0 ),	/* 0 */
/* 772 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 774 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 776 */	NdrFcShort( 0x10 ),	/* 16 */
/* 778 */	NdrFcShort( 0x0 ),	/* 0 */
/* 780 */	NdrFcShort( 0x8 ),	/* Offset= 8 (788) */
/* 782 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 784 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 786 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 788 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 790 */	NdrFcShort( 0xffca ),	/* Offset= -54 (736) */
/* 792 */	
			0x11, 0x0,	/* FC_RP */
/* 794 */	NdrFcShort( 0x8 ),	/* Offset= 8 (802) */
/* 796 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 798 */	NdrFcShort( 0x8 ),	/* 8 */
/* 800 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 802 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 804 */	NdrFcShort( 0x10 ),	/* 16 */
/* 806 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 808 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (796) */
/* 810 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 812 */	NdrFcShort( 0xfdb8 ),	/* Offset= -584 (228) */
/* 814 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 816 */	
			0x12, 0x0,	/* FC_UP */
/* 818 */	NdrFcShort( 0x70 ),	/* Offset= 112 (930) */
/* 820 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 822 */	NdrFcShort( 0x6 ),	/* 6 */
/* 824 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 826 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 828 */	NdrFcShort( 0x6 ),	/* 6 */
/* 830 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 832 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (820) */
/* 834 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 836 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 838 */	NdrFcShort( 0x4 ),	/* 4 */
/* 840 */	0x4,		/* Corr desc: FC_USMALL */
			0x0,		/*  */
/* 842 */	NdrFcShort( 0xfff9 ),	/* -7 */
/* 844 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 846 */	0x0 , 
			0x0,		/* 0 */
/* 848 */	NdrFcLong( 0x0 ),	/* 0 */
/* 852 */	NdrFcLong( 0x0 ),	/* 0 */
/* 856 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 858 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 860 */	NdrFcShort( 0x8 ),	/* 8 */
/* 862 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (836) */
/* 864 */	0x2,		/* FC_CHAR */
			0x2,		/* FC_CHAR */
/* 866 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 868 */	NdrFcShort( 0xffd6 ),	/* Offset= -42 (826) */
/* 870 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 872 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 874 */	NdrFcShort( 0x10 ),	/* 16 */
/* 876 */	NdrFcShort( 0x0 ),	/* 0 */
/* 878 */	NdrFcShort( 0x6 ),	/* Offset= 6 (884) */
/* 880 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 882 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 884 */	
			0x12, 0x0,	/* FC_UP */
/* 886 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (858) */
/* 888 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 890 */	NdrFcShort( 0x0 ),	/* 0 */
/* 892 */	0x8,		/* Corr desc: FC_LONG */
			0x0,		/*  */
/* 894 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 896 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 898 */	0x0 , 
			0x0,		/* 0 */
/* 900 */	NdrFcLong( 0x0 ),	/* 0 */
/* 904 */	NdrFcLong( 0x0 ),	/* 0 */
/* 908 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 912 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 914 */	0x0 , 
			0x0,		/* 0 */
/* 916 */	NdrFcLong( 0x0 ),	/* 0 */
/* 920 */	NdrFcLong( 0x0 ),	/* 0 */
/* 924 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 926 */	NdrFcShort( 0xffca ),	/* Offset= -54 (872) */
/* 928 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 930 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 932 */	NdrFcShort( 0x8 ),	/* 8 */
/* 934 */	NdrFcShort( 0xffd2 ),	/* Offset= -46 (888) */
/* 936 */	NdrFcShort( 0x0 ),	/* Offset= 0 (936) */
/* 938 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 940 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 942 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 944 */	0xb,		/* FC_HYPER */
			0x5c,		/* FC_PAD */
/* 946 */	
			0x11, 0x0,	/* FC_RP */
/* 948 */	NdrFcShort( 0xfd30 ),	/* Offset= -720 (228) */
/* 950 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 952 */	NdrFcShort( 0x2 ),	/* Offset= 2 (954) */
/* 954 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 956 */	NdrFcShort( 0x30 ),	/* 48 */
/* 958 */	0xb,		/* FC_HYPER */
			0xb,		/* FC_HYPER */
/* 960 */	0xb,		/* FC_HYPER */
			0xb,		/* FC_HYPER */
/* 962 */	0xb,		/* FC_HYPER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 964 */	0x0,		/* 0 */
			NdrFcShort( 0xfd45 ),	/* Offset= -699 (266) */
			0x5b,		/* FC_END */
/* 968 */	
			0x11, 0x0,	/* FC_RP */
/* 970 */	NdrFcShort( 0xff90 ),	/* Offset= -112 (858) */
/* 972 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 974 */	NdrFcShort( 0xfcfc ),	/* Offset= -772 (202) */
/* 976 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 978 */	0x6,		/* FC_SHORT */
			0x5c,		/* FC_PAD */
/* 980 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 982 */	0xb9,		/* FC_UINT3264 */
			0x5c,		/* FC_PAD */

			0x0
        }
    };

static const unsigned short DefaultIfName_FormatStringOffsetTable[] =
    {
    0,
    62,
    106,
    150,
    224,
    346,
    408,
    572,
    634,
    702,
    770,
    832,
    894,
    1028,
    1102,
    1170
    };



#endif /* defined(_M_AMD64)*/



/* this ALWAYS GENERATED file contains the RPC client stubs */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 03:14:07 2038
 */
/* Compiler settings for sspi.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if defined(_M_AMD64)




#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif


#include "ndr64types.h"
#include "pshpack8.h"


typedef 
NDR64_FORMAT_CHAR
__midl_frag242_t;
extern const __midl_frag242_t __midl_frag242;

typedef 
NDR64_FORMAT_CHAR
__midl_frag241_t;
extern const __midl_frag241_t __midl_frag241;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag240_t;
extern const __midl_frag240_t __midl_frag240;

typedef 
struct _NDR64_CONTEXT_HANDLE_FORMAT
__midl_frag239_t;
extern const __midl_frag239_t __midl_frag239;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
}
__midl_frag238_t;
extern const __midl_frag238_t __midl_frag238;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag235_t;
extern const __midl_frag235_t __midl_frag235;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag234_t;
extern const __midl_frag234_t __midl_frag234;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag232_t;
extern const __midl_frag232_t __midl_frag232;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
}
__midl_frag230_t;
extern const __midl_frag230_t __midl_frag230;

typedef 
NDR64_FORMAT_CHAR
__midl_frag228_t;
extern const __midl_frag228_t __midl_frag228;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag227_t;
extern const __midl_frag227_t __midl_frag227;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag224_t;
extern const __midl_frag224_t __midl_frag224;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
    struct _NDR64_PARAM_FORMAT frag9;
}
__midl_frag221_t;
extern const __midl_frag221_t __midl_frag221;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
}
__midl_frag219_t;
extern const __midl_frag219_t __midl_frag219;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag218_t;
extern const __midl_frag218_t __midl_frag218;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag215_t;
extern const __midl_frag215_t __midl_frag215;

typedef 
NDR64_FORMAT_CHAR
__midl_frag208_t;
extern const __midl_frag208_t __midl_frag208;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_NOOP frag2;
    struct _NDR64_EXPR_CONST64 frag3;
}
__midl_frag207_t;
extern const __midl_frag207_t __midl_frag207;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag206_t;
extern const __midl_frag206_t __midl_frag206;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag205_t;
extern const __midl_frag205_t __midl_frag205;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_NO_REPEAT_FORMAT frag1;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2;
        struct _NDR64_POINTER_FORMAT frag3;
        NDR64_FORMAT_CHAR frag4;
    } frag2;
}
__midl_frag203_t;
extern const __midl_frag203_t __midl_frag203;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag201_t;
extern const __midl_frag201_t __midl_frag201;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag200_t;
extern const __midl_frag200_t __midl_frag200;

typedef 
struct 
{
    struct _NDR64_CONF_STRUCTURE_HEADER_FORMAT frag1;
}
__midl_frag199_t;
extern const __midl_frag199_t __midl_frag199;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag198_t;
extern const __midl_frag198_t __midl_frag198;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_REPEAT_FORMAT frag1;
        struct 
        {
            struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag1;
            struct _NDR64_POINTER_FORMAT frag2;
        } frag2;
        NDR64_FORMAT_CHAR frag3;
    } frag2;
    struct _NDR64_ARRAY_ELEMENT_INFO frag3;
}
__midl_frag197_t;
extern const __midl_frag197_t __midl_frag197;

typedef 
struct 
{
    struct _NDR64_CONF_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_MEMPAD_FORMAT frag2;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag3;
    } frag2;
}
__midl_frag196_t;
extern const __midl_frag196_t __midl_frag196;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag195_t;
extern const __midl_frag195_t __midl_frag195;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
}
__midl_frag194_t;
extern const __midl_frag194_t __midl_frag194;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag193_t;
extern const __midl_frag193_t __midl_frag193;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag192_t;
extern const __midl_frag192_t __midl_frag192;

typedef 
struct 
{
    struct _NDR64_POINTER_FORMAT frag1;
}
__midl_frag189_t;
extern const __midl_frag189_t __midl_frag189;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_NOOP frag2;
    struct _NDR64_EXPR_CONST64 frag3;
}
__midl_frag188_t;
extern const __midl_frag188_t __midl_frag188;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag187_t;
extern const __midl_frag187_t __midl_frag187;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag186_t;
extern const __midl_frag186_t __midl_frag186;

typedef 
struct 
{
    struct _NDR64_CONF_VAR_ARRAY_HEADER_FORMAT frag1;
}
__midl_frag185_t;
extern const __midl_frag185_t __midl_frag185;

typedef 
struct 
{
    struct _NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag2;
        struct _NDR64_MEMPAD_FORMAT frag3;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag4;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag5;
    } frag2;
}
__midl_frag184_t;
extern const __midl_frag184_t __midl_frag184;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag183_t;
extern const __midl_frag183_t __midl_frag183;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
    struct _NDR64_PARAM_FORMAT frag9;
    struct _NDR64_PARAM_FORMAT frag10;
    struct _NDR64_PARAM_FORMAT frag11;
    struct _NDR64_PARAM_FORMAT frag12;
    struct _NDR64_PARAM_FORMAT frag13;
    struct _NDR64_PARAM_FORMAT frag14;
    struct _NDR64_PARAM_FORMAT frag15;
    struct _NDR64_PARAM_FORMAT frag16;
    struct _NDR64_PARAM_FORMAT frag17;
    struct _NDR64_PARAM_FORMAT frag18;
    struct _NDR64_PARAM_FORMAT frag19;
}
__midl_frag180_t;
extern const __midl_frag180_t __midl_frag180;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag178_t;
extern const __midl_frag178_t __midl_frag178;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
}
__midl_frag174_t;
extern const __midl_frag174_t __midl_frag174;

typedef 
struct _NDR64_RANGED_STRING_FORMAT
__midl_frag172_t;
extern const __midl_frag172_t __midl_frag172;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_NO_REPEAT_FORMAT frag1;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2;
        struct _NDR64_POINTER_FORMAT frag3;
        struct _NDR64_NO_REPEAT_FORMAT frag4;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag5;
        struct _NDR64_POINTER_FORMAT frag6;
        NDR64_FORMAT_CHAR frag7;
    } frag2;
}
__midl_frag170_t;
extern const __midl_frag170_t __midl_frag170;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag169_t;
extern const __midl_frag169_t __midl_frag169;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
}
__midl_frag165_t;
extern const __midl_frag165_t __midl_frag165;

typedef 
struct 
{
    struct _NDR64_POINTER_FORMAT frag1;
    struct _NDR64_POINTER_FORMAT frag2;
}
__midl_frag163_t;
extern const __midl_frag163_t __midl_frag163;

typedef 
struct _NDR64_CONFORMANT_STRING_FORMAT
__midl_frag162_t;
extern const __midl_frag162_t __midl_frag162;

typedef 
struct 
{
    struct _NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag2;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag3;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag4;
        struct _NDR64_MEMPAD_FORMAT frag5;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag6;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag7;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag8;
    } frag2;
}
__midl_frag160_t;
extern const __midl_frag160_t __midl_frag160;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_NO_REPEAT_FORMAT frag1;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2;
        struct _NDR64_POINTER_FORMAT frag3;
        NDR64_FORMAT_CHAR frag4;
    } frag2;
}
__midl_frag159_t;
extern const __midl_frag159_t __midl_frag159;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag158_t;
extern const __midl_frag158_t __midl_frag158;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag156_t;
extern const __midl_frag156_t __midl_frag156;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag155_t;
extern const __midl_frag155_t __midl_frag155;

typedef 
struct 
{
    struct _NDR64_NON_ENCAPSULATED_UNION frag1;
    struct _NDR64_UNION_ARM_SELECTOR frag2;
    struct _NDR64_UNION_ARM frag3;
    struct _NDR64_UNION_ARM frag4;
    NDR64_UINT32 frag5;
}
__midl_frag154_t;
extern const __midl_frag154_t __midl_frag154;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag153_t;
extern const __midl_frag153_t __midl_frag153;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
}
__midl_frag148_t;
extern const __midl_frag148_t __midl_frag148;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
}
__midl_frag146_t;
extern const __midl_frag146_t __midl_frag146;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag145_t;
extern const __midl_frag145_t __midl_frag145;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
}
__midl_frag144_t;
extern const __midl_frag144_t __midl_frag144;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag143_t;
extern const __midl_frag143_t __midl_frag143;

typedef 
struct 
{
    struct _NDR64_POINTER_FORMAT frag1;
}
__midl_frag142_t;
extern const __midl_frag142_t __midl_frag142;

typedef 
struct 
{
    struct _NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_MEMPAD_FORMAT frag2;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag3;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag4;
    } frag2;
}
__midl_frag140_t;
extern const __midl_frag140_t __midl_frag140;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag139_t;
extern const __midl_frag139_t __midl_frag139;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_NO_REPEAT_FORMAT frag1;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2;
        struct _NDR64_POINTER_FORMAT frag3;
        NDR64_FORMAT_CHAR frag4;
    } frag2;
}
__midl_frag137_t;
extern const __midl_frag137_t __midl_frag137;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag136_t;
extern const __midl_frag136_t __midl_frag136;

typedef 
struct 
{
    struct _NDR64_NON_ENCAPSULATED_UNION frag1;
    struct _NDR64_UNION_ARM_SELECTOR frag2;
    struct _NDR64_UNION_ARM frag3;
    struct _NDR64_UNION_ARM frag4;
    struct _NDR64_UNION_ARM frag5;
    struct _NDR64_UNION_ARM frag6;
    NDR64_UINT32 frag7;
}
__midl_frag134_t;
extern const __midl_frag134_t __midl_frag134;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag133_t;
extern const __midl_frag133_t __midl_frag133;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
}
__midl_frag128_t;
extern const __midl_frag128_t __midl_frag128;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag126_t;
extern const __midl_frag126_t __midl_frag126;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
}
__midl_frag122_t;
extern const __midl_frag122_t __midl_frag122;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag119_t;
extern const __midl_frag119_t __midl_frag119;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag116_t;
extern const __midl_frag116_t __midl_frag116;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag113_t;
extern const __midl_frag113_t __midl_frag113;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag112_t;
extern const __midl_frag112_t __midl_frag112;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag111_t;
extern const __midl_frag111_t __midl_frag111;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag110_t;
extern const __midl_frag110_t __midl_frag110;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag109_t;
extern const __midl_frag109_t __midl_frag109;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag107_t;
extern const __midl_frag107_t __midl_frag107;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag106_t;
extern const __midl_frag106_t __midl_frag106;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_NO_REPEAT_FORMAT frag1;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2;
        struct _NDR64_POINTER_FORMAT frag3;
        NDR64_FORMAT_CHAR frag4;
    } frag2;
}
__midl_frag105_t;
extern const __midl_frag105_t __midl_frag105;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag104_t;
extern const __midl_frag104_t __midl_frag104;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag102_t;
extern const __midl_frag102_t __midl_frag102;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_NO_REPEAT_FORMAT frag1;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2;
        struct _NDR64_POINTER_FORMAT frag3;
        NDR64_FORMAT_CHAR frag4;
    } frag2;
}
__midl_frag101_t;
extern const __midl_frag101_t __midl_frag101;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_REPEAT_FORMAT frag1;
        struct 
        {
            struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag1;
            struct _NDR64_POINTER_FORMAT frag2;
        } frag2;
        NDR64_FORMAT_CHAR frag3;
    } frag2;
    struct _NDR64_ARRAY_ELEMENT_INFO frag3;
}
__midl_frag97_t;
extern const __midl_frag97_t __midl_frag97;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_NO_REPEAT_FORMAT frag1;
        struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT frag2;
        struct _NDR64_POINTER_FORMAT frag3;
        NDR64_FORMAT_CHAR frag4;
    } frag2;
}
__midl_frag96_t;
extern const __midl_frag96_t __midl_frag96;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag93_t;
extern const __midl_frag93_t __midl_frag93;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag84_t;
extern const __midl_frag84_t __midl_frag84;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag82_t;
extern const __midl_frag82_t __midl_frag82;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
    struct _NDR64_PARAM_FORMAT frag9;
    struct _NDR64_PARAM_FORMAT frag10;
    struct _NDR64_PARAM_FORMAT frag11;
    struct _NDR64_PARAM_FORMAT frag12;
    struct _NDR64_PARAM_FORMAT frag13;
    struct _NDR64_PARAM_FORMAT frag14;
    struct _NDR64_PARAM_FORMAT frag15;
    struct _NDR64_PARAM_FORMAT frag16;
    struct _NDR64_PARAM_FORMAT frag17;
    struct _NDR64_PARAM_FORMAT frag18;
    struct _NDR64_PARAM_FORMAT frag19;
    struct _NDR64_PARAM_FORMAT frag20;
    struct _NDR64_PARAM_FORMAT frag21;
    struct _NDR64_PARAM_FORMAT frag22;
    struct _NDR64_PARAM_FORMAT frag23;
    struct _NDR64_PARAM_FORMAT frag24;
}
__midl_frag79_t;
extern const __midl_frag79_t __midl_frag79;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
}
__midl_frag69_t;
extern const __midl_frag69_t __midl_frag69;

typedef 
struct 
{
    struct _NDR64_STRUCTURE_HEADER_FORMAT frag1;
}
__midl_frag67_t;
extern const __midl_frag67_t __midl_frag67;

typedef 
struct 
{
    struct _NDR64_POINTER_FORMAT frag1;
}
__midl_frag62_t;
extern const __midl_frag62_t __midl_frag62;

typedef 
struct 
{
    struct _NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_MEMPAD_FORMAT frag2;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag3;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag4;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag5;
    } frag2;
}
__midl_frag58_t;
extern const __midl_frag58_t __midl_frag58;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag53_t;
extern const __midl_frag53_t __midl_frag53;

typedef 
struct 
{
    struct _NDR64_POINTER_FORMAT frag1;
}
__midl_frag52_t;
extern const __midl_frag52_t __midl_frag52;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_OPERATOR frag2;
    struct _NDR64_EXPR_VAR frag3;
    struct _NDR64_EXPR_CONST64 frag4;
}
__midl_frag50_t;
extern const __midl_frag50_t __midl_frag50;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_OPERATOR frag2;
    struct _NDR64_EXPR_VAR frag3;
    struct _NDR64_EXPR_CONST64 frag4;
}
__midl_frag49_t;
extern const __midl_frag49_t __midl_frag49;

typedef 
struct 
{
    struct _NDR64_CONF_VAR_ARRAY_HEADER_FORMAT frag1;
}
__midl_frag48_t;
extern const __midl_frag48_t __midl_frag48;

typedef 
struct 
{
    struct _NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag2;
        struct _NDR64_MEMPAD_FORMAT frag3;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag4;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag5;
    } frag2;
}
__midl_frag47_t;
extern const __midl_frag47_t __midl_frag47;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
    struct _NDR64_PARAM_FORMAT frag9;
    struct _NDR64_PARAM_FORMAT frag10;
    struct _NDR64_PARAM_FORMAT frag11;
    struct _NDR64_PARAM_FORMAT frag12;
    struct _NDR64_PARAM_FORMAT frag13;
    struct _NDR64_PARAM_FORMAT frag14;
    struct _NDR64_PARAM_FORMAT frag15;
    struct _NDR64_PARAM_FORMAT frag16;
    struct _NDR64_PARAM_FORMAT frag17;
}
__midl_frag42_t;
extern const __midl_frag42_t __midl_frag42;

typedef 
struct 
{
    struct _NDR64_POINTER_FORMAT frag1;
}
__midl_frag40_t;
extern const __midl_frag40_t __midl_frag40;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag38_t;
extern const __midl_frag38_t __midl_frag38;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag37_t;
extern const __midl_frag37_t __midl_frag37;

typedef 
struct 
{
    struct _NDR64_BOGUS_STRUCTURE_HEADER_FORMAT frag1;
    struct 
    {
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag1;
        struct _NDR64_MEMPAD_FORMAT frag2;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag3;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag4;
        struct _NDR64_BUFFER_ALIGN_FORMAT frag5;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag6;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag7;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag8;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag9;
        struct _NDR64_MEMPAD_FORMAT frag10;
        struct _NDR64_BUFFER_ALIGN_FORMAT frag11;
        struct _NDR64_SIMPLE_MEMBER_FORMAT frag12;
    } frag2;
}
__midl_frag36_t;
extern const __midl_frag36_t __midl_frag36;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_OPERATOR frag2;
    struct _NDR64_EXPR_VAR frag3;
}
__midl_frag33_t;
extern const __midl_frag33_t __midl_frag33;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag32_t;
extern const __midl_frag32_t __midl_frag32;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag31_t;
extern const __midl_frag31_t __midl_frag31;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag30_t;
extern const __midl_frag30_t __midl_frag30;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_VAR frag2;
}
__midl_frag26_t;
extern const __midl_frag26_t __midl_frag26;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag25_t;
extern const __midl_frag25_t __midl_frag25;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag24_t;
extern const __midl_frag24_t __midl_frag24;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
    struct _NDR64_PARAM_FORMAT frag8;
    struct _NDR64_PARAM_FORMAT frag9;
}
__midl_frag21_t;
extern const __midl_frag21_t __midl_frag21;

typedef 
struct _NDR64_CONTEXT_HANDLE_FORMAT
__midl_frag19_t;
extern const __midl_frag19_t __midl_frag19;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag18_t;
extern const __midl_frag18_t __midl_frag18;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
}
__midl_frag17_t;
extern const __midl_frag17_t __midl_frag17;

typedef 
struct _NDR64_CONTEXT_HANDLE_FORMAT
__midl_frag11_t;
extern const __midl_frag11_t __midl_frag11;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag10_t;
extern const __midl_frag10_t __midl_frag10;

typedef 
struct _NDR64_CONFORMANT_STRING_FORMAT
__midl_frag4_t;
extern const __midl_frag4_t __midl_frag4;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag3_t;
extern const __midl_frag3_t __midl_frag3;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_PARAM_FORMAT frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
    struct _NDR64_PARAM_FORMAT frag6;
    struct _NDR64_PARAM_FORMAT frag7;
}
__midl_frag2_t;
extern const __midl_frag2_t __midl_frag2;

typedef 
NDR64_FORMAT_UINT32
__midl_frag1_t;
extern const __midl_frag1_t __midl_frag1;

static const __midl_frag242_t __midl_frag242 =
0x5    /* FC64_INT32 */;

static const __midl_frag241_t __midl_frag241 =
0x7    /* FC64_INT64 */;

static const __midl_frag240_t __midl_frag240 =
{ 
/* *__int3264 */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 12 /* 0xc */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag241
};

static const __midl_frag239_t __midl_frag239 =
{ 
/* struct _NDR64_CONTEXT_HANDLE_FORMAT */
    0x70,    /* FC64_BIND_CONTEXT */
    (NDR64_UINT8) 65 /* 0x41 */,
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT8) 0 /* 0x0 */
};

static const __midl_frag238_t __midl_frag238 =
{ 
/* Proc15_SspirGetInprocDispatchTable */
    { 
    /* Proc15_SspirGetInprocDispatchTable */      /* procedure Proc15_SspirGetInprocDispatchTable */
        (NDR64_UINT32) 17301568 /* 0x1080040 */,    /* explicit handle */ /* IsIntrepreted, HasReturn, HasExtensions */
        (NDR64_UINT32) 24 /* 0x18 */ ,  /* Stack size */
        (NDR64_UINT32) 36 /* 0x24 */,
        (NDR64_UINT32) 48 /* 0x30 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 3 /* 0x3 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag241,
        { 
        /* arg_1 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    }
};

static const __midl_frag235_t __midl_frag235 =
{ 
/* *long */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 12 /* 0xc */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag242
};

static const __midl_frag234_t __midl_frag234 =
{ 
/* *Struct_222_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag47
};

static const __midl_frag232_t __midl_frag232 =
{ 
/* *Struct_172_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag67
};

static const __midl_frag230_t __midl_frag230 =
{ 
/* Proc14_SspirGetUserName */
    { 
    /* Proc14_SspirGetUserName */      /* procedure Proc14_SspirGetUserName */
        (NDR64_UINT32) 21626944 /* 0x14a0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, HasReturn, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 48 /* 0x30 */ ,  /* Stack size */
        (NDR64_UINT32) 100 /* 0x64 */,
        (NDR64_UINT32) 40 /* 0x28 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 6 /* 0x6 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag242,
        { 
        /* arg_2 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag47,
        { 
        /* arg_3 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag242,
        { 
        /* arg_4 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    }
};

static const __midl_frag228_t __midl_frag228 =
0x4    /* FC64_INT16 */;

static const __midl_frag227_t __midl_frag227 =
{ 
/* *short */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 12 /* 0xc */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag228
};

static const __midl_frag224_t __midl_frag224 =
{ 
/* *Struct_1072_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag199
};

static const __midl_frag221_t __midl_frag221 =
{ 
/* Proc13_SspirLookupAccountSid */
    { 
    /* Proc13_SspirLookupAccountSid */      /* procedure Proc13_SspirLookupAccountSid */
        (NDR64_UINT32) 23986240 /* 0x16e0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, ClientMustSize, HasReturn, ServerCorrelation, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 56 /* 0x38 */ ,  /* Stack size */
        (NDR64_UINT32) 92 /* 0x5c */,
        (NDR64_UINT32) 38 /* 0x26 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 7 /* 0x7 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag199,
        { 
        /* arg_2 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag47,
        { 
        /* arg_3 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag47,
        { 
        /* arg_4 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* arg_5 */      /* parameter arg_5 */
        &__midl_frag228,
        { 
        /* arg_5 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        48 /* 0x30 */,   /* Stack offset */
    }
};

static const __midl_frag219_t __midl_frag219 =
{ 
/* Struct_1206_t */
    { 
    /* Struct_1206_t */
        0x30,    /* FC64_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_1206_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 48 /* 0x30 */
    }
};

static const __midl_frag218_t __midl_frag218 =
{ 
/* *Struct_1206_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag219
};

static const __midl_frag215_t __midl_frag215 =
{ 
/* *Struct_248_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag144
};

static const __midl_frag208_t __midl_frag208 =
0x10    /* FC64_CHAR */;

static const __midl_frag207_t __midl_frag207 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_NOOP */
        0x5,    /* FC_EXPR_PAD */
        (NDR64_UINT8) 4 /* 0x4 */,
        (NDR64_UINT16) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_EXPR_CONST64 */
        0x2,    /* FC_EXPR_CONST64 */
        0x7,    /* FC64_INT64 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT64) 32 /* 0x20 */
    }
};

static const __midl_frag206_t __midl_frag206 =
{ 
/* *char */
    { 
    /* *char */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 0 /* 0x0 */,
        { 
        /* *char */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag207
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag208
    }
};

static const __midl_frag205_t __midl_frag205 =
{ 
/* *char */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 32 /* 0x20 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag206
};

static const __midl_frag203_t __midl_frag203 =
{ 
/* Struct_1086_t */
    { 
    /* Struct_1086_t */
        0x31,    /* FC64_PSTRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_1086_t */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */
    },
    { 
    /*  */
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *Struct_1072_t */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag199
        },
        0x93    /* FC64_END */
    }
};

static const __midl_frag201_t __midl_frag201 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x1,    /* FC64_UINT8 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */
    }
};

static const __midl_frag200_t __midl_frag200 =
{ 
/*  */
    { 
    /* struct _NDR64_CONF_ARRAY_HEADER_FORMAT */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 3 /* 0x3 */,
        { 
        /* struct _NDR64_CONF_ARRAY_HEADER_FORMAT */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 4 /* 0x4 */,
        &__midl_frag201
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 4 /* 0x4 */,
        &__midl_frag242
    }
};

static const __midl_frag199_t __midl_frag199 =
{ 
/* Struct_1072_t */
    { 
    /* Struct_1072_t */
        0x32,    /* FC64_CONF_STRUCT */
        (NDR64_UINT8) 3 /* 0x3 */,
        { 
        /* Struct_1072_t */
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 8 /* 0x8 */,
        &__midl_frag200
    }
};

static const __midl_frag198_t __midl_frag198 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x5,    /* FC64_INT32 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 0 /* 0x0 */
    }
};

static const __midl_frag197_t __midl_frag197 =
{ 
/*  */
    { 
    /* struct _NDR64_CONF_ARRAY_HEADER_FORMAT */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* struct _NDR64_CONF_ARRAY_HEADER_FORMAT */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */,
        &__midl_frag198
    },
    { 
    /*  */
        { 
        /* struct _NDR64_REPEAT_FORMAT */
            0x82,    /* FC64_VARIABLE_REPEAT */
            { 
            /* struct _NDR64_REPEAT_FORMAT */
                (NDR64_UINT8) 1 /* 0x1 */,
                (NDR64_UINT8) 0 /* 0x0 */
            },
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 16 /* 0x10 */,
            (NDR64_UINT32) 0 /* 0x0 */,
            (NDR64_UINT32) 1 /* 0x1 */
        },
        { 
        /*  */
            { 
            /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
                (NDR64_UINT32) 0 /* 0x0 */,
                (NDR64_UINT32) 0 /* 0x0 */
            },
            { 
            /* *Struct_1072_t */
                0x21,    /* FC64_UP */
                (NDR64_UINT8) 0 /* 0x0 */,
                (NDR64_UINT16) 0 /* 0x0 */,
                &__midl_frag199
            }
        },
        0x93    /* FC64_END */
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 16 /* 0x10 */,
        &__midl_frag203
    }
};

static const __midl_frag196_t __midl_frag196 =
{ 
/* Struct_1144_t */
    { 
    /* Struct_1144_t */
        0x37,    /* FC64_FORCED_CONF_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_1144_t */
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 1 /* 0x1 */,
        (NDR64_UINT32) 8 /* 0x8 */,
        0,
        0,
        0,
        &__midl_frag197,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag195_t __midl_frag195 =
{ 
/* *Struct_1144_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag196
};

static const __midl_frag194_t __midl_frag194 =
{ 
/* Struct_1016_t */
    { 
    /* Struct_1016_t */
        0x30,    /* FC64_STRUCT */
        (NDR64_UINT8) 3 /* 0x3 */,
        { 
        /* Struct_1016_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */
    }
};

static const __midl_frag193_t __midl_frag193 =
{ 
/* *Struct_1016_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag194
};

static const __midl_frag192_t __midl_frag192 =
{ 
/* *Struct_282_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag58
};

static const __midl_frag189_t __midl_frag189 =
{ 
/*  */
    { 
    /* *char */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 32 /* 0x20 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag185
    }
};

static const __midl_frag188_t __midl_frag188 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_NOOP */
        0x5,    /* FC_EXPR_PAD */
        (NDR64_UINT8) 4 /* 0x4 */,
        (NDR64_UINT16) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_EXPR_CONST64 */
        0x2,    /* FC_EXPR_CONST64 */
        0x7,    /* FC64_INT64 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT64) 0 /* 0x0 */
    }
};

static const __midl_frag187_t __midl_frag187 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x4,    /* FC64_INT16 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 0 /* 0x0 */
    }
};

static const __midl_frag186_t __midl_frag186 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x4,    /* FC64_INT16 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 2 /* 0x2 */
    }
};

static const __midl_frag185_t __midl_frag185 =
{ 
/* *char */
    { 
    /* *char */
        0x43,    /* FC64_CONFVAR_ARRAY */
        (NDR64_UINT8) 0 /* 0x0 */,
        { 
        /* *char */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag186,
        &__midl_frag187
    }
};

static const __midl_frag184_t __midl_frag184 =
{ 
/* Struct_984_t */
    { 
    /* Struct_984_t */
        0x35,    /* FC64_FORCED_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_984_t */
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */,
        0,
        0,
        &__midl_frag189,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x4,    /* FC64_INT16 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x4,    /* FC64_INT16 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag183_t __midl_frag183 =
{ 
/* *Struct_984_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag184
};

static const __midl_frag180_t __midl_frag180 =
{ 
/* Proc12_SspirLogonUser */
    { 
    /* Proc12_SspirLogonUser */      /* procedure Proc12_SspirLogonUser */
        (NDR64_UINT32) 19660864 /* 0x12c0040 */,    /* explicit handle */ /* IsIntrepreted, ClientMustSize, HasReturn, ServerCorrelation, HasExtensions */
        (NDR64_UINT32) 136 /* 0x88 */ ,  /* Stack size */
        (NDR64_UINT32) 234 /* 0xea */,
        (NDR64_UINT32) 288 /* 0x120 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 17 /* 0x11 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag184,
        { 
        /* arg_2 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag228,
        { 
        /* arg_3 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag242,
        { 
        /* arg_4 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* arg_5 */      /* parameter arg_5 */
        &__midl_frag58,
        { 
        /* arg_5 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    },
    { 
    /* arg_6 */      /* parameter arg_6 */
        &__midl_frag194,
        { 
        /* arg_6 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        48 /* 0x30 */,   /* Stack offset */
    },
    { 
    /* arg_7 */      /* parameter arg_7 */
        &__midl_frag195,
        { 
        /* arg_7 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        56 /* 0x38 */,   /* Stack offset */
    },
    { 
    /* arg_8 */      /* parameter arg_8 */
        &__midl_frag242,
        { 
        /* arg_8 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        64 /* 0x40 */,   /* Stack offset */
    },
    { 
    /* arg_9 */      /* parameter arg_9 */
        &__midl_frag205,
        { 
        /* arg_9 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        72 /* 0x48 */,   /* Stack offset */
    },
    { 
    /* arg_10 */      /* parameter arg_10 */
        &__midl_frag242,
        { 
        /* arg_10 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        80 /* 0x50 */,   /* Stack offset */
    },
    { 
    /* arg_11 */      /* parameter arg_11 */
        &__midl_frag241,
        { 
        /* arg_11 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        88 /* 0x58 */,   /* Stack offset */
    },
    { 
    /* arg_12 */      /* parameter arg_12 */
        &__midl_frag242,
        { 
        /* arg_12 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        96 /* 0x60 */,   /* Stack offset */
    },
    { 
    /* arg_13 */      /* parameter arg_13 */
        &__midl_frag144,
        { 
        /* arg_13 */
            0,
            1,
            0,
            1,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], [out], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        104 /* 0x68 */,   /* Stack offset */
    },
    { 
    /* arg_14 */      /* parameter arg_14 */
        &__midl_frag241,
        { 
        /* arg_14 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        112 /* 0x70 */,   /* Stack offset */
    },
    { 
    /* arg_15 */      /* parameter arg_15 */
        &__midl_frag219,
        { 
        /* arg_15 */
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        120 /* 0x78 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        128 /* 0x80 */,   /* Stack offset */
    }
};

static const __midl_frag178_t __midl_frag178 =
{ 
/* *Struct_446_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag96
};

static const __midl_frag174_t __midl_frag174 =
{ 
/* Proc11_SspirApplyControlToken */
    { 
    /* Proc11_SspirApplyControlToken */      /* procedure Proc11_SspirApplyControlToken */
        (NDR64_UINT32) 19660864 /* 0x12c0040 */,    /* explicit handle */ /* IsIntrepreted, ClientMustSize, HasReturn, ServerCorrelation, HasExtensions */
        (NDR64_UINT32) 40 /* 0x28 */ ,  /* Stack size */
        (NDR64_UINT32) 148 /* 0x94 */,
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 5 /* 0x5 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag67,
        { 
        /* arg_2 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag96,
        { 
        /* arg_3 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    }
};

static const __midl_frag172_t __midl_frag172 =
{ 
/* *wchar_t */
    { 
    /* *wchar_t */
        0x64,    /* FC64_CONF_WCHAR_STRING */
        { 
        /* *wchar_t */
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT16) 2 /* 0x2 */
    },
    (NDR64_UINT32) 0 /* 0x0 */,
    (NDR64_UINT64) 0 /* 0x0 */,
    (NDR64_UINT64) 65535 /* 0xffff */
};

static const __midl_frag170_t __midl_frag170 =
{ 
/* Struct_888_t */
    { 
    /* Struct_888_t */
        0x31,    /* FC64_PSTRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_888_t */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 56 /* 0x38 */
    },
    { 
    /*  */
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 40 /* 0x28 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *wchar_t */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag172
        },
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 48 /* 0x30 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *wchar_t */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag172
        },
        0x93    /* FC64_END */
    }
};

static const __midl_frag169_t __midl_frag169 =
{ 
/* *Struct_888_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag170
};

static const __midl_frag165_t __midl_frag165 =
{ 
/* Proc10_SspirSslSetCredentialsAttributes */
    { 
    /* Proc10_SspirSslSetCredentialsAttributes */      /* procedure Proc10_SspirSslSetCredentialsAttributes */
        (NDR64_UINT32) 17563712 /* 0x10c0040 */,    /* explicit handle */ /* IsIntrepreted, ClientMustSize, HasReturn, HasExtensions */
        (NDR64_UINT32) 40 /* 0x28 */ ,  /* Stack size */
        (NDR64_UINT32) 148 /* 0x94 */,
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 5 /* 0x5 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag67,
        { 
        /* arg_2 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag170,
        { 
        /* arg_3 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    }
};

static const __midl_frag163_t __midl_frag163 =
{ 
/*  */
    { 
    /* *wchar_t */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag162
    },
    { 
    /* *wchar_t */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag162
    }
};

static const __midl_frag162_t __midl_frag162 =
{ 
/* *wchar_t */
    { 
    /* *wchar_t */
        0x64,    /* FC64_CONF_WCHAR_STRING */
        { 
        /* *wchar_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT16) 2 /* 0x2 */
    }
};

static const __midl_frag160_t __midl_frag160 =
{ 
/* Struct_786_t */
    { 
    /* Struct_786_t */
        0x35,    /* FC64_FORCED_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_786_t */
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 32 /* 0x20 */,
        0,
        0,
        &__midl_frag163,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x4,    /* FC64_INT16 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x4,    /* FC64_INT16 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag159_t __midl_frag159 =
{ 
/* Struct_810_t */
    { 
    /* Struct_810_t */
        0x31,    /* FC64_PSTRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_810_t */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */
    },
    { 
    /*  */
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *Struct_786_t */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag160
        },
        0x93    /* FC64_END */
    }
};

static const __midl_frag158_t __midl_frag158 =
{ 
/* *Struct_810_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag159
};

static const __midl_frag156_t __midl_frag156 =
{ 
/* *Struct_772_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag194
};

static const __midl_frag155_t __midl_frag155 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x5,    /* FC64_INT32 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 24 /* 0x18 */  /* Offset */
    }
};

static const __midl_frag154_t __midl_frag154 =
{ 
/* union_750 */
    { 
    /* union_750 */
        0x51,    /* FC64_NON_ENCAPSULATED_UNION */
        (NDR64_UINT8) 7 /* 0x7 */,
        (NDR64_UINT8) 0 /* 0x0 */,
        0x5,    /* FC64_INT32 */
        (NDR64_UINT32) 8 /* 0x8 */,
        &__midl_frag155,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_UNION_ARM_SELECTOR */
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT8) 7 /* 0x7 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 2 /* 0x2 */
    },
    { 
    /* struct _NDR64_UNION_ARM */
        (NDR64_INT64) 0 /* 0x0 */,
        &__midl_frag156,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_UNION_ARM */
        (NDR64_INT64) 12 /* 0xc */,
        &__midl_frag158,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    (NDR64_UINT32) 0 /* 0x0 */
};

static const __midl_frag153_t __midl_frag153 =
{ 
/* *union_750 */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag154
};

static const __midl_frag148_t __midl_frag148 =
{ 
/* Proc9_SspirNegQueryContextAttributes */
    { 
    /* Proc9_SspirNegQueryContextAttributes */      /* procedure Proc9_SspirNegQueryContextAttributes */
        (NDR64_UINT32) 21626944 /* 0x14a0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, HasReturn, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 48 /* 0x30 */ ,  /* Stack size */
        (NDR64_UINT32) 156 /* 0x9c */,
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 6 /* 0x6 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag67,
        { 
        /* arg_2 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag242,
        { 
        /* arg_3 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag154,
        { 
        /* arg_4 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    }
};

static const __midl_frag146_t __midl_frag146 =
{ 
/* Struct_708_t */
    { 
    /* Struct_708_t */
        0x30,    /* FC64_STRUCT */
        (NDR64_UINT8) 3 /* 0x3 */,
        { 
        /* Struct_708_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 4 /* 0x4 */
    }
};

static const __midl_frag145_t __midl_frag145 =
{ 
/* *Struct_708_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag146
};

static const __midl_frag144_t __midl_frag144 =
{ 
/* Struct_696_t */
    { 
    /* Struct_696_t */
        0x30,    /* FC64_STRUCT */
        (NDR64_UINT8) 3 /* 0x3 */,
        { 
        /* Struct_696_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 8 /* 0x8 */
    }
};

static const __midl_frag143_t __midl_frag143 =
{ 
/* *Struct_696_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag144
};

static const __midl_frag142_t __midl_frag142 =
{ 
/*  */
    { 
    /* *long */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 8 /* 0x8 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag242
    }
};

static const __midl_frag140_t __midl_frag140 =
{ 
/* Struct_676_t */
    { 
    /* Struct_676_t */
        0x35,    /* FC64_FORCED_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_676_t */
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */,
        0,
        0,
        &__midl_frag142,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag139_t __midl_frag139 =
{ 
/* *Struct_676_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag140
};

static const __midl_frag137_t __midl_frag137 =
{ 
/* Struct_658_t */
    { 
    /* Struct_658_t */
        0x31,    /* FC64_PSTRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_658_t */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 8 /* 0x8 */
    },
    { 
    /*  */
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *wchar_t */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag162
        },
        0x93    /* FC64_END */
    }
};

static const __midl_frag136_t __midl_frag136 =
{ 
/* *Struct_658_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag137
};

static const __midl_frag134_t __midl_frag134 =
{ 
/* union_624 */
    { 
    /* union_624 */
        0x51,    /* FC64_NON_ENCAPSULATED_UNION */
        (NDR64_UINT8) 7 /* 0x7 */,
        (NDR64_UINT8) 0 /* 0x0 */,
        0x5,    /* FC64_INT32 */
        (NDR64_UINT32) 8 /* 0x8 */,
        &__midl_frag155,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_UNION_ARM_SELECTOR */
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT8) 7 /* 0x7 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 4 /* 0x4 */
    },
    { 
    /* struct _NDR64_UNION_ARM */
        (NDR64_INT64) 1 /* 0x1 */,
        &__midl_frag136,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_UNION_ARM */
        (NDR64_INT64) 86 /* 0x56 */,
        &__midl_frag139,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_UNION_ARM */
        (NDR64_INT64) 87 /* 0x57 */,
        &__midl_frag143,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_UNION_ARM */
        (NDR64_INT64) 88 /* 0x58 */,
        &__midl_frag145,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    (NDR64_UINT32) 0 /* 0x0 */
};

static const __midl_frag133_t __midl_frag133 =
{ 
/* *union_624 */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag134
};

static const __midl_frag128_t __midl_frag128 =
{ 
/* Proc8_SspirSslQueryCredentialsAttributes */
    { 
    /* Proc8_SspirSslQueryCredentialsAttributes */      /* procedure Proc8_SspirSslQueryCredentialsAttributes */
        (NDR64_UINT32) 21626944 /* 0x14a0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, HasReturn, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 48 /* 0x30 */ ,  /* Stack size */
        (NDR64_UINT32) 156 /* 0x9c */,
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 6 /* 0x6 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag67,
        { 
        /* arg_2 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag242,
        { 
        /* arg_3 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag134,
        { 
        /* arg_4 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    }
};

static const __midl_frag126_t __midl_frag126 =
{ 
/* *Struct_144_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag36
};

static const __midl_frag122_t __midl_frag122 =
{ 
/* Proc7_SspirDeleteSecurityContext */
    { 
    /* Proc7_SspirDeleteSecurityContext */      /* procedure Proc7_SspirDeleteSecurityContext */
        (NDR64_UINT32) 21626944 /* 0x14a0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, HasReturn, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 40 /* 0x28 */ ,  /* Stack size */
        (NDR64_UINT32) 148 /* 0x94 */,
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 5 /* 0x5 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag67,
        { 
        /* arg_2 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag36,
        { 
        /* arg_3 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    }
};

static const __midl_frag119_t __midl_frag119 =
{ 
/* *Struct_144_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag36
};

static const __midl_frag116_t __midl_frag116 =
{ 
/* *Struct_316_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag69
};

static const __midl_frag113_t __midl_frag113 =
{ 
/* *Struct_304_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag67
};

static const __midl_frag112_t __midl_frag112 =
{ 
/* *Struct_128_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag101
};

static const __midl_frag111_t __midl_frag111 =
{ 
/* *Struct_516_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag105
};

static const __midl_frag110_t __midl_frag110 =
{ 
/* **Struct_516_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 20 /* 0x14 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag111
};

static const __midl_frag109_t __midl_frag109 =
{ 
/* *Struct_446_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag96
};

static const __midl_frag107_t __midl_frag107 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x5,    /* FC64_INT32 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 4 /* 0x4 */
    }
};

static const __midl_frag106_t __midl_frag106 =
{ 
/* *Struct_466_t */
    { 
    /* *Struct_466_t */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 3 /* 0x3 */,
        { 
        /* *Struct_466_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 8 /* 0x8 */,
        &__midl_frag107
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 8 /* 0x8 */,
        &__midl_frag144
    }
};

static const __midl_frag105_t __midl_frag105 =
{ 
/* Struct_516_t */
    { 
    /* Struct_516_t */
        0x31,    /* FC64_PSTRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_516_t */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */
    },
    { 
    /*  */
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 8 /* 0x8 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *Struct_466_t */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 32 /* 0x20 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag106
        },
        0x93    /* FC64_END */
    }
};

static const __midl_frag104_t __midl_frag104 =
{ 
/* *Struct_516_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag105
};

static const __midl_frag102_t __midl_frag102 =
{ 
/* *char */
    { 
    /* *char */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 0 /* 0x0 */,
        { 
        /* *char */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag198
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag208
    }
};

static const __midl_frag101_t __midl_frag101 =
{ 
/* Struct_128_t */
    { 
    /* Struct_128_t */
        0x31,    /* FC64_PSTRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_128_t */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */
    },
    { 
    /*  */
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 8 /* 0x8 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *char */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 32 /* 0x20 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag102
        },
        0x93    /* FC64_END */
    }
};

static const __midl_frag97_t __midl_frag97 =
{ 
/* *Struct_128_t */
    { 
    /* *Struct_128_t */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* *Struct_128_t */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */,
        &__midl_frag107
    },
    { 
    /*  */
        { 
        /* struct _NDR64_REPEAT_FORMAT */
            0x82,    /* FC64_VARIABLE_REPEAT */
            { 
            /* struct _NDR64_REPEAT_FORMAT */
                (NDR64_UINT8) 1 /* 0x1 */,
                (NDR64_UINT8) 0 /* 0x0 */
            },
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 16 /* 0x10 */,
            (NDR64_UINT32) 0 /* 0x0 */,
            (NDR64_UINT32) 1 /* 0x1 */
        },
        { 
        /*  */
            { 
            /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
                (NDR64_UINT32) 8 /* 0x8 */,
                (NDR64_UINT32) 0 /* 0x0 */
            },
            { 
            /* *char */
                0x21,    /* FC64_UP */
                (NDR64_UINT8) 32 /* 0x20 */,
                (NDR64_UINT16) 0 /* 0x0 */,
                &__midl_frag102
            }
        },
        0x93    /* FC64_END */
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 16 /* 0x10 */,
        &__midl_frag101
    }
};

static const __midl_frag96_t __midl_frag96 =
{ 
/* Struct_446_t */
    { 
    /* Struct_446_t */
        0x31,    /* FC64_PSTRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_446_t */
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */
    },
    { 
    /*  */
        { 
        /* struct _NDR64_NO_REPEAT_FORMAT */
            0x80,    /* FC64_NO_REPEAT */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_POINTER_INSTANCE_HEADER_FORMAT */
            (NDR64_UINT32) 8 /* 0x8 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* *Struct_128_t */
            0x21,    /* FC64_UP */
            (NDR64_UINT8) 32 /* 0x20 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            &__midl_frag97
        },
        0x93    /* FC64_END */
    }
};

static const __midl_frag93_t __midl_frag93 =
{ 
/* *wchar_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag162
};

static const __midl_frag84_t __midl_frag84 =
{ 
/* *Struct_222_t */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag47
};

static const __midl_frag82_t __midl_frag82 =
{ 
/* *long */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 8 /* 0x8 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag242
};

static const __midl_frag79_t __midl_frag79 =
{ 
/* Proc6_SspirProcessSecurityContext */
    { 
    /* Proc6_SspirProcessSecurityContext */      /* procedure Proc6_SspirProcessSecurityContext */
        (NDR64_UINT32) 23986240 /* 0x16e0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, ClientMustSize, HasReturn, ServerCorrelation, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 176 /* 0xb0 */ ,  /* Stack size */
        (NDR64_UINT32) 252 /* 0xfc */,
        (NDR64_UINT32) 208 /* 0xd0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 22 /* 0x16 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag242,
        { 
        /* arg_2 */
            0,
            0,
            0,
            1,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], [out], Basetype, SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag84,
        { 
        /* arg_3 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag67,
        { 
        /* arg_4 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* arg_5 */      /* parameter arg_5 */
        &__midl_frag67,
        { 
        /* arg_5 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    },
    { 
    /* arg_6 */      /* parameter arg_6 */
        &__midl_frag242,
        { 
        /* arg_6 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        48 /* 0x30 */,   /* Stack offset */
    },
    { 
    /* arg_7 */      /* parameter arg_7 */
        &__midl_frag242,
        { 
        /* arg_7 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        56 /* 0x38 */,   /* Stack offset */
    },
    { 
    /* arg_8 */      /* parameter arg_8 */
        &__midl_frag205,
        { 
        /* arg_8 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        64 /* 0x40 */,   /* Stack offset */
    },
    { 
    /* arg_9 */      /* parameter arg_9 */
        &__midl_frag93,
        { 
        /* arg_9 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        72 /* 0x48 */,   /* Stack offset */
    },
    { 
    /* arg_10 */      /* parameter arg_10 */
        &__midl_frag96,
        { 
        /* arg_10 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        80 /* 0x50 */,   /* Stack offset */
    },
    { 
    /* arg_11 */      /* parameter arg_11 */
        &__midl_frag105,
        { 
        /* arg_11 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        88 /* 0x58 */,   /* Stack offset */
    },
    { 
    /* arg_12 */      /* parameter arg_12 */
        &__midl_frag96,
        { 
        /* arg_12 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        96 /* 0x60 */,   /* Stack offset */
    },
    { 
    /* arg_13 */      /* parameter arg_13 */
        &__midl_frag110,
        { 
        /* arg_13 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        104 /* 0x68 */,   /* Stack offset */
    },
    { 
    /* arg_14 */      /* parameter arg_14 */
        &__midl_frag101,
        { 
        /* arg_14 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        112 /* 0x70 */,   /* Stack offset */
    },
    { 
    /* arg_15 */      /* parameter arg_15 */
        &__midl_frag67,
        { 
        /* arg_15 */
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        120 /* 0x78 */,   /* Stack offset */
    },
    { 
    /* arg_16 */      /* parameter arg_16 */
        &__midl_frag242,
        { 
        /* arg_16 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        128 /* 0x80 */,   /* Stack offset */
    },
    { 
    /* arg_17 */      /* parameter arg_17 */
        &__midl_frag69,
        { 
        /* arg_17 */
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        136 /* 0x88 */,   /* Stack offset */
    },
    { 
    /* arg_18 */      /* parameter arg_18 */
        &__midl_frag242,
        { 
        /* arg_18 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        144 /* 0x90 */,   /* Stack offset */
    },
    { 
    /* arg_19 */      /* parameter arg_19 */
        &__midl_frag36,
        { 
        /* arg_19 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        152 /* 0x98 */,   /* Stack offset */
    },
    { 
    /* arg_20 */      /* parameter arg_20 */
        &__midl_frag36,
        { 
        /* arg_20 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        160 /* 0xa0 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        168 /* 0xa8 */,   /* Stack offset */
    }
};

static const __midl_frag69_t __midl_frag69 =
{ 
/* Struct_316_t */
    { 
    /* Struct_316_t */
        0x30,    /* FC64_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_316_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 8 /* 0x8 */
    }
};

static const __midl_frag67_t __midl_frag67 =
{ 
/* Struct_304_t */
    { 
    /* Struct_304_t */
        0x30,    /* FC64_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_304_t */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */
    }
};

static const __midl_frag62_t __midl_frag62 =
{ 
/*  */
    { 
    /* *char */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 32 /* 0x20 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag102
    }
};

static const __midl_frag58_t __midl_frag58 =
{ 
/* Struct_282_t */
    { 
    /* Struct_282_t */
        0x35,    /* FC64_FORCED_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_282_t */
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 24 /* 0x18 */,
        0,
        0,
        &__midl_frag62,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x7,    /* FC64_INT64 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag53_t __midl_frag53 =
{ 
/* *Struct_222_t */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag47
};

static const __midl_frag52_t __midl_frag52 =
{ 
/*  */
    { 
    /* *short */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 32 /* 0x20 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag48
    }
};

static const __midl_frag50_t __midl_frag50 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_OPERATOR */
        0x4,    /* FC_EXPR_OPER */
        0x11,    /* OP_SLASH */
        0x0,    /* FC64_ZERO */
        (NDR64_UINT8) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x4,    /* FC64_INT16 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_EXPR_CONST64 */
        0x2,    /* FC_EXPR_CONST64 */
        0x7,    /* FC64_INT64 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT64) 2 /* 0x2 */
    }
};

static const __midl_frag49_t __midl_frag49 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_OPERATOR */
        0x4,    /* FC_EXPR_OPER */
        0x11,    /* OP_SLASH */
        0x0,    /* FC64_ZERO */
        (NDR64_UINT8) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x4,    /* FC64_INT16 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 2 /* 0x2 */
    },
    { 
    /* struct _NDR64_EXPR_CONST64 */
        0x2,    /* FC_EXPR_CONST64 */
        0x7,    /* FC64_INT64 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT64) 2 /* 0x2 */
    }
};

static const __midl_frag48_t __midl_frag48 =
{ 
/* *short */
    { 
    /* *short */
        0x43,    /* FC64_CONFVAR_ARRAY */
        (NDR64_UINT8) 1 /* 0x1 */,
        { 
        /* *short */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 2 /* 0x2 */,
        &__midl_frag49,
        &__midl_frag50
    }
};

static const __midl_frag47_t __midl_frag47 =
{ 
/* Struct_222_t */
    { 
    /* Struct_222_t */
        0x35,    /* FC64_FORCED_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_222_t */
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */,
        0,
        0,
        &__midl_frag52,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x4,    /* FC64_INT16 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x4,    /* FC64_INT16 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag42_t __midl_frag42 =
{ 
/* Proc4_SspirAcquireCredentialsHandle */
    { 
    /* Proc4_SspirAcquireCredentialsHandle */      /* procedure Proc4_SspirAcquireCredentialsHandle */
        (NDR64_UINT32) 23986240 /* 0x16e0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, ClientMustSize, HasReturn, ServerCorrelation, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 120 /* 0x78 */ ,  /* Stack size */
        (NDR64_UINT32) 188 /* 0xbc */,
        (NDR64_UINT32) 112 /* 0x70 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 15 /* 0xf */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag67,
        { 
        /* arg_1 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag84,
        { 
        /* arg_2 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag47,
        { 
        /* arg_3 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag242,
        { 
        /* arg_4 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* arg_5 */      /* parameter arg_5 */
        &__midl_frag143,
        { 
        /* arg_5 */
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    },
    { 
    /* arg_6 */      /* parameter arg_6 */
        &__midl_frag58,
        { 
        /* arg_6 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        48 /* 0x30 */,   /* Stack offset */
    },
    { 
    /* arg_7 */      /* parameter arg_7 */
        &__midl_frag241,
        { 
        /* arg_7 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        56 /* 0x38 */,   /* Stack offset */
    },
    { 
    /* arg_8 */      /* parameter arg_8 */
        &__midl_frag241,
        { 
        /* arg_8 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        64 /* 0x40 */,   /* Stack offset */
    },
    { 
    /* arg_9 */      /* parameter arg_9 */
        &__midl_frag242,
        { 
        /* arg_9 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        72 /* 0x48 */,   /* Stack offset */
    },
    { 
    /* arg_10 */      /* parameter arg_10 */
        &__midl_frag67,
        { 
        /* arg_10 */
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        80 /* 0x50 */,   /* Stack offset */
    },
    { 
    /* arg_11 */      /* parameter arg_11 */
        &__midl_frag69,
        { 
        /* arg_11 */
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        88 /* 0x58 */,   /* Stack offset */
    },
    { 
    /* arg_12 */      /* parameter arg_12 */
        &__midl_frag36,
        { 
        /* arg_12 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        96 /* 0x60 */,   /* Stack offset */
    },
    { 
    /* arg_13 */      /* parameter arg_13 */
        &__midl_frag36,
        { 
        /* arg_13 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        104 /* 0x68 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        112 /* 0x70 */,   /* Stack offset */
    }
};

static const __midl_frag40_t __midl_frag40 =
{ 
/*  */
    { 
    /* *char */
        0x21,    /* FC64_UP */
        (NDR64_UINT8) 32 /* 0x20 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        &__midl_frag37
    }
};

static const __midl_frag38_t __midl_frag38 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x5,    /* FC64_INT32 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 24 /* 0x18 */
    }
};

static const __midl_frag37_t __midl_frag37 =
{ 
/* *char */
    { 
    /* *char */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 0 /* 0x0 */,
        { 
        /* *char */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag38
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag208
    }
};

static const __midl_frag36_t __midl_frag36 =
{ 
/* Struct_144_t */
    { 
    /* Struct_144_t */
        0x35,    /* FC64_FORCED_BOGUS_STRUCT */
        (NDR64_UINT8) 7 /* 0x7 */,
        { 
        /* Struct_144_t */
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 48 /* 0x30 */,
        0,
        0,
        &__midl_frag40,
    },
    { 
    /*  */
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 4 /* 0x4 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x7,    /* FC64_INT64 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x7,    /* FC64_INT64 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* Struct_128_t */
            0x92,    /* FC64_BUFFER_ALIGN */
            (NDR64_UINT8) 7 /* 0x7 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x5,    /* FC64_INT32 */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x14,    /* FC64_POINTER */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x10,    /* FC64_CHAR */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_MEMPAD_FORMAT */
            0x90,    /* FC64_STRUCTPADN */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 7 /* 0x7 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* Struct_144_t */
            0x92,    /* FC64_BUFFER_ALIGN */
            (NDR64_UINT8) 7 /* 0x7 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        },
        { 
        /* struct _NDR64_SIMPLE_MEMBER_FORMAT */
            0x93,    /* FC64_END */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT16) 0 /* 0x0 */,
            (NDR64_UINT32) 0 /* 0x0 */
        }
    }
};

static const __midl_frag33_t __midl_frag33 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_OPERATOR */
        0x4,    /* FC_EXPR_OPER */
        0x5,    /* OP_UNARY_INDIRECTION */
        0x5,    /* FC64_INT32 */
        (NDR64_UINT8) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x7,    /* FC64_INT64 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 24 /* 0x18 */  /* Offset */
    }
};

static const __midl_frag32_t __midl_frag32 =
{ 
/* *char */
    { 
    /* *char */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 0 /* 0x0 */,
        { 
        /* *char */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag33
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag208
    }
};

static const __midl_frag31_t __midl_frag31 =
{ 
/* *char */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 32 /* 0x20 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag32
};

static const __midl_frag30_t __midl_frag30 =
{ 
/* **char */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 20 /* 0x14 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag31
};

static const __midl_frag26_t __midl_frag26 =
{ 
/*  */
    (NDR64_UINT32) 1 /* 0x1 */,
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x5,    /* FC64_INT32 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 8 /* 0x8 */  /* Offset */
    }
};

static const __midl_frag25_t __midl_frag25 =
{ 
/* *char */
    { 
    /* *char */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 0 /* 0x0 */,
        { 
        /* *char */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag26
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag208
    }
};

static const __midl_frag24_t __midl_frag24 =
{ 
/* *char */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag25
};

static const __midl_frag21_t __midl_frag21 =
{ 
/* Proc3_SspirCallRpc */
    { 
    /* Proc3_SspirCallRpc */      /* procedure Proc3_SspirCallRpc */
        (NDR64_UINT32) 23986240 /* 0x16e0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, ClientMustSize, HasReturn, ServerCorrelation, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 56 /* 0x38 */ ,  /* Stack size */
        (NDR64_UINT32) 44 /* 0x2c */,
        (NDR64_UINT32) 40 /* 0x28 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 7 /* 0x7 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 64 /* 0x40 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag239,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag242,
        { 
        /* arg_1 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag25,
        { 
        /* arg_2 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag242,
        { 
        /* arg_3 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag30,
        { 
        /* arg_4 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* arg_5 */      /* parameter arg_5 */
        &__midl_frag36,
        { 
        /* arg_5 */
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* MustSize, MustFree, [out], SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        48 /* 0x30 */,   /* Stack offset */
    }
};

static const __midl_frag19_t __midl_frag19 =
{ 
/* struct _NDR64_CONTEXT_HANDLE_FORMAT */
    0x70,    /* FC64_BIND_CONTEXT */
    (NDR64_UINT8) 225 /* 0xe1 */,
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT8) 0 /* 0x0 */
};

static const __midl_frag18_t __midl_frag18 =
{ 
/* *struct _NDR64_POINTER_FORMAT */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag19
};

static const __midl_frag17_t __midl_frag17 =
{ 
/* Proc2_SspirDisconnectRpc */
    { 
    /* Proc2_SspirDisconnectRpc */      /* procedure Proc2_SspirDisconnectRpc */
        (NDR64_UINT32) 17301568 /* 0x1080040 */,    /* explicit handle */ /* IsIntrepreted, HasReturn, HasExtensions */
        (NDR64_UINT32) 16 /* 0x10 */ ,  /* Stack size */
        (NDR64_UINT32) 60 /* 0x3c */,
        (NDR64_UINT32) 68 /* 0x44 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 2 /* 0x2 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x70,    /* FC64_BIND_CONTEXT */
            (NDR64_UINT8) 224 /* 0xe0 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_0 */      /* parameter arg_0 */
        &__midl_frag19,
        { 
        /* arg_0 */
            0,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], [out], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    }
};

static const __midl_frag11_t __midl_frag11 =
{ 
/* struct _NDR64_CONTEXT_HANDLE_FORMAT */
    0x70,    /* FC64_BIND_CONTEXT */
    (NDR64_UINT8) 160 /* 0xa0 */,
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT8) 0 /* 0x0 */
};

static const __midl_frag10_t __midl_frag10 =
{ 
/* *struct _NDR64_POINTER_FORMAT */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 4 /* 0x4 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag11
};

static const __midl_frag4_t __midl_frag4 =
{ 
/* *char */
    { 
    /* *char */
        0x63,    /* FC64_CONF_CHAR_STRING */
        { 
        /* *char */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT16) 1 /* 0x1 */
    }
};

static const __midl_frag3_t __midl_frag3 =
{ 
/* *char */
    0x21,    /* FC64_UP */
    (NDR64_UINT8) 0 /* 0x0 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag4
};

static const __midl_frag2_t __midl_frag2 =
{ 
/* Proc0_SspirConnectRpc */
    { 
    /* Proc0_SspirConnectRpc */      /* procedure Proc0_SspirConnectRpc */
        (NDR64_UINT32) 786498 /* 0xc0042 */,    /* primitive handle */ /* IsIntrepreted, ClientMustSize, HasReturn */
        (NDR64_UINT32) 48 /* 0x30 */ ,  /* Stack size */
        (NDR64_UINT32) 8 /* 0x8 */,
        (NDR64_UINT32) 132 /* 0x84 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 6 /* 0x6 */,
        (NDR64_UINT16) 0 /* 0x0 */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag3,
        { 
        /* arg_1 */
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in] */
        (NDR64_UINT16) 0 /* 0x0 */,
        0 /* 0x0 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag242,
        { 
        /* arg_2 */
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_3 */      /* parameter arg_3 */
        &__midl_frag242,
        { 
        /* arg_3 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* arg_4 */      /* parameter arg_4 */
        &__midl_frag242,
        { 
        /* arg_4 */
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            1
        },    /* [out], Basetype, SimpleRef, UseCache */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    },
    { 
    /* arg_5 */      /* parameter arg_5 */
        &__midl_frag11,
        { 
        /* arg_5 */
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        32 /* 0x20 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag242,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        40 /* 0x28 */,   /* Stack offset */
    }
};

static const __midl_frag1_t __midl_frag1 =
(NDR64_UINT32) 0 /* 0x0 */;


#include "poppack.h"


static const FormatInfoRef DefaultIfName_Ndr64ProcTable[] =
    {
    &__midl_frag2,
    &__midl_frag17,
    &__midl_frag17,
    &__midl_frag21,
    &__midl_frag42,
    &__midl_frag122,
    &__midl_frag79,
    &__midl_frag122,
    &__midl_frag128,
    &__midl_frag148,
    &__midl_frag165,
    &__midl_frag174,
    &__midl_frag180,
    &__midl_frag221,
    &__midl_frag230,
    &__midl_frag238
    };


static const MIDL_STUB_DESC DefaultIfName_StubDesc = 
    {
    (void *)& DefaultIfName___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &default_IfHandle,
    0,
    0,
    0,
    0,
    sspi__MIDL_TypeFormatString.Format,
    1, /* -error bounds_check flag */
    0x60001, /* Ndr library version */
    0,
    0x801026e, /* MIDL Version 8.1.622 */
    0,
    0,
    0,  /* notify & notify_flag routine table */
    0x2000001, /* MIDL flag */
    0, /* cs routines */
    (void *)& DefaultIfName_ProxyInfo,   /* proxy/server info */
    0
    };

static const MIDL_SYNTAX_INFO DefaultIfName_SyntaxInfo [  2 ] = 
    {
    {
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    sspi__MIDL_ProcFormatString.Format,
    DefaultIfName_FormatStringOffsetTable,
    sspi__MIDL_TypeFormatString.Format,
    0,
    0,
    0
    }
    ,{
    {{0x71710533,0xbeba,0x4937,{0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36}},{1,0}},
    0,
    0 ,
    (unsigned short *) DefaultIfName_Ndr64ProcTable,
    0,
    0,
    0,
    0
    }
    };

static const MIDL_STUBLESS_PROXY_INFO DefaultIfName_ProxyInfo =
    {
    &DefaultIfName_StubDesc,
    sspi__MIDL_ProcFormatString.Format,
    DefaultIfName_FormatStringOffsetTable,
    (RPC_SYNTAX_IDENTIFIER*)&_RpcTransferSyntax,
    2,
    (MIDL_SYNTAX_INFO*)DefaultIfName_SyntaxInfo
    
    };

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif


#endif /* defined(_M_AMD64)*/

