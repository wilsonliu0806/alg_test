
/*
 * $Id: typedefs.h,v 1.151 2006/09/02 14:08:42 hno Exp $
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_TYPEDEFS_H
#define SQUID_TYPEDEFS_H
//#include "fs/aufs/async_io.h"

typedef unsigned int store_status_t;
typedef unsigned int mem_status_t;
typedef unsigned int ping_status_t;
typedef unsigned int swap_status_t;
typedef signed int sfileno;
typedef signed int sdirno;
typedef unsigned int monitor_status_t;

#if SIZEOF_INT64_T > SIZEOF_LONG && HAVE_STRTOLL
typedef int64_t squid_off_t;
#define SIZEOF_SQUID_OFF_T SIZEOF_INT64_T
#define PRINTF_OFF_T PRId64
#define strto_off_t (int64_t)strtoll
#else
typedef long squid_off_t;
#define SIZEOF_SQUID_OFF_T SIZEOF_LONG
#define PRINTF_OFF_T "ld"
#define strto_off_t strtol
#endif

#if LARGE_CACHE_FILES
typedef squid_off_t squid_file_sz;
#define SIZEOF_SQUID_FILE_SZ SIZEOF_SQUID_OFF_T
#else
typedef size_t squid_file_sz;
#define SIZEOF_SQUID_FILE_SZ SIZEOF_SIZE_T
#endif

typedef struct {
	squid_off_t bytes;
	squid_off_t kb;
} kb_t;

typedef struct {
	size_t count;
	size_t bytes;
	size_t gb;
} gb_t;

/*
 * grep '^struct' structs.h \
 * | perl -ne '($a,$b)=split;$c=$b;$c=~s/^_//; print "typedef struct $b $c;\n";'
 */

typedef struct _acl_ip_data acl_ip_data;
typedef struct _acl_time_data acl_time_data;
typedef struct _acl_name_list acl_name_list;
typedef struct _acl_deny_info_list acl_deny_info_list;
typedef struct _auth_user_t auth_user_t;
typedef struct _auth_user_request_t auth_user_request_t;
typedef struct _auth_user_hash_pointer auth_user_hash_pointer;
typedef struct _auth_user_ip_t auth_user_ip_t;
typedef struct _acl_proxy_auth_match_cache acl_proxy_auth_match_cache;
typedef struct _acl_hdr_data acl_hdr_data;
typedef struct _authscheme_entry authscheme_entry_t;
typedef struct _authScheme authScheme;
typedef struct _encrypt_style Encrypt_style;
typedef struct _fixed_item Fixed_item;
typedef struct _bitrate_limit Bitrate_limit;
typedef struct _attr_pos_pair Attr_pos_pair;
typedef struct _pcreget  Pcre_get;
typedef struct _btv_time_key_entry BtvTimeKeyEntry;
typedef struct _list_plus_int_entry ListPlusIntEntry;
typedef struct _speed_info_entry SpeedCalcEntry;
typedef struct _list_node list_node;
typedef struct _ip_list_table ip_list_table;
typedef struct _encrypt_req_style Encrypt_req_style;
typedef struct _encrypt_pattern Encrypt_pattern;
typedef struct _wasu_verify_style wasu_verify_style;
typedef struct _timestamp_fail_redirect Timestamp_fail_redirect; 

#if USE_SSL
typedef struct _acl_cert_data acl_cert_data;
#endif
typedef struct _acl_user_data acl_user_data;
typedef struct _acl_user_ip_data acl_user_ip_data;
typedef struct _acl_arp_data acl_arp_data;
typedef struct _acl_request_type acl_request_type;
typedef struct _acl acl;
typedef struct _acl_snmp_comm acl_snmp_comm;
typedef struct _acl_list acl_list;
typedef struct _center_verify_key center_verify_key;
typedef struct _forward_access_url forward_access_url;
typedef struct _acl_access acl_access;
typedef struct _acl_address acl_address;
typedef struct _acl_tos acl_tos;
typedef struct _aclCheck_t aclCheck_t;
typedef struct _deskeylist deskeylist;
typedef struct _wordlist wordlist;
typedef struct _mgrtrafficdata mgrtrafficdata;
typedef struct _intlist intlist;
typedef struct _acl_intlist acl_intlist;
typedef struct _encrypt_key encrypt_key;
typedef struct _qiyi_key qiyi_key;
typedef struct _intrange intrange;
typedef int wsacc_level;
typedef struct _wsacc_level_rule wsacc_level_rule;
typedef struct _wsacc_level_acl wsacc_level_acl;
typedef struct _ushortlist ushortlist;
typedef struct _relist relist;
typedef struct _hierarchy hierarchy;
typedef struct _sockaddr_in_list sockaddr_in_list;
typedef struct _http_port_list http_port_list;
typedef struct _https_port_list https_port_list;
typedef struct _https_sni_list https_sni_list;
typedef struct _sq_ip_alias_rbtree_node_t sq_ip_alias_rbtree_node_t;
typedef struct _hostData hostData;
typedef struct _SquidConfig SquidConfig;
typedef struct _SquidConfig2 SquidConfig2;
typedef struct _close_handler close_handler;
typedef struct _dread_ctrl dread_ctrl;
typedef struct _dwrite_q dwrite_q;
typedef struct _ETag ETag;
typedef struct _fde fde;
typedef struct _fileMap fileMap;
typedef struct _HttpReply http_reply;
typedef struct _HttpStatusLine HttpStatusLine;
typedef struct _HttpHeaderFieldAttrs HttpHeaderFieldAttrs;
typedef struct _HttpHeaderFieldInfo HttpHeaderFieldInfo;
typedef struct _HttpHeader HttpHeader;
typedef struct _HttpHdrCc HttpHdrCc;
typedef struct _HttpHdrRangeSpec HttpHdrRangeSpec;
typedef struct _HttpHdrRange HttpHdrRange;
typedef struct _HttpHdrRangeIter HttpHdrRangeIter;
typedef struct _HttpHdrContRange HttpHdrContRange;
typedef struct _TimeOrTag TimeOrTag;
typedef struct _HttpHeaderEntry HttpHeaderEntry;
typedef struct _HttpHeaderFieldStat HttpHeaderFieldStat;
typedef struct _HttpHeaderStat HttpHeaderStat;
typedef struct _HttpBody HttpBody;
typedef struct _HttpReply HttpReply;
typedef struct _HttpStateData HttpStateData;
typedef struct _icpUdpData icpUdpData;
typedef struct _clientHttpRequest clientHttpRequest;
typedef struct _peer_node peer_node;
typedef struct _ConnStateData ConnStateData;
typedef struct _ConnCloseHelperData ConnCloseHelperData;
typedef struct _ipcache_addrs ipcache_addrs;
typedef struct _domain_ping domain_ping;
typedef struct _domain_type domain_type;
typedef struct _DynPool DynPool;
typedef struct _Packer Packer;
typedef struct _StoreDigestCBlock StoreDigestCBlock;
typedef struct _DigestFetchState DigestFetchState;
typedef struct _PeerDigest PeerDigest;
typedef struct _peer peer;
typedef struct _center_verify_peer center_verify_peer;
typedef struct _anti_verify_peer anti_verify_peer;
typedef struct _cache_swaplow_time cache_swaplow_time;
typedef struct _time_bucket time_bucket;
typedef struct _net_db_name net_db_name;
typedef struct _ForwardIpString ForwardIpString;
typedef struct _net_db_peer net_db_peer;
typedef struct _netdbEntry netdbEntry;
typedef struct _ping_data ping_data;
typedef struct _ps_state ps_state;
typedef struct _Notification Notification;
typedef struct _IpdbRequest IpdbRequest;

typedef struct _HierarchyLogEntry HierarchyLogEntry;
typedef struct _FdMsgLog FdMsgLog;
typedef struct _pingerEchoData pingerEchoData;
typedef struct _pingerReplyData pingerReplyData;
typedef struct _icp_common_t icp_common_t;
typedef struct _Meta_data Meta_data;
typedef struct _iostats iostats;
typedef struct _MemBuf MemBuf;
typedef struct _mem_node mem_node;
typedef struct _mem_hdr mem_hdr;
typedef struct _store_client store_client;
typedef struct _MemObject MemObject;
typedef struct _MemDisk MemDisk;
typedef struct _StoreEntryMin StoreEntryMin;
typedef struct _CookieCacheEntry CookieCacheEntry;
typedef struct _V56CacheEntry V56CacheEntry;
typedef struct _ipCheckListEntry IpAccessIdentEntry;
typedef struct _ipBlackListEntry IpBlackListEntry;
typedef struct _PurgeDir PurgeDir;
typedef struct _PurgeEntry PurgeEntry;
typedef struct _purge_url_t purge_url_t;
typedef struct _store_partition store_partition;
typedef struct _store_resume store_resume;
typedef struct _StoreEntry StoreEntry;
typedef struct _FlvFrameHeadMsg FlvFrameHeadMsg;
typedef struct _SwapDir SwapDir;
typedef struct _request_flags request_flags;
typedef struct _helper_flags helper_flags;
typedef struct _helper_stateful_flags helper_stateful_flags;
typedef struct _http_state_flags http_state_flags;
typedef struct _Replacement Replacement;
typedef struct _header_mangler header_mangler;
typedef struct _header_mangler2 header_mangler2;
typedef struct _redirector_mangler redirector_mangler;
typedef struct _cache_dir_use_tmpfs cache_dir_use_tmpfs;
typedef struct _rewrite_vary rewrite_vary;
typedef struct _replace_domain_mangler replace_domain_mangler;
typedef struct _replace_domain_acl replace_domain_acl;
typedef struct _replace_port_acl replace_port_acl;
typedef struct _url_ignore_key_mangler url_ignore_key_mangler;
typedef struct _regex_replacer regex_replacer;
typedef struct _regex_replace regex_replace;
typedef struct _conhash_uri_regex_replace conhash_uri_regex_replace;
typedef struct _body_size body_size;
typedef struct _crc_context_t crc_context_t;
typedef struct _zip_crc_context_t zip_crc_context_t;
typedef struct _retrieve_block_t retrieve_block_t;
typedef struct _retrieve_key_t retrieve_key_t;
typedef struct _retrieve_t retrieve_t;
typedef struct _download_content_check_block_t download_content_check_block_t;
typedef struct _download_content_check_t download_content_check_t;
typedef struct _hash_check hash_check;
typedef struct _download_content_check_block_t realtime_content_check_block_t;
typedef struct _download_content_check_t realtime_content_check_t;
typedef struct _realtime_hash_check_t realtime_hash_check_t;
typedef struct _request_t request_t;
typedef struct _AccessLogEntry AccessLogEntry;
typedef struct _cachemgr_passwd cachemgr_passwd;
typedef struct _moserver moserver;
typedef struct _refresh_t refresh_t;
typedef struct _refresh_hash_entry refresh_hash_entry;
typedef struct _CommWriteStateData CommWriteStateData;
typedef struct _ErrorState ErrorState;
typedef struct _PeersDepends PeersDepends;
typedef struct _dlink_node dlink_node;
typedef struct _dlink_list dlink_list;
typedef struct _dlink_func dlink_func;
typedef struct _StatCounters StatCounters;
typedef struct _tlv tlv;
typedef struct _err_forward err_forward;
typedef struct _int_list int_list;
typedef struct _storeSwapLogData storeSwapLogData;
typedef struct _storeSwapLogData4Old storeSwapLogData4Old;
typedef struct _storeSwapLogDataMmap storeSwapLogDataMmap;
typedef struct _storeSwapLogDataOld storeSwapLogDataOld;
typedef struct _storeSwapLogHeader storeSwapLogHeader;
typedef struct _NegativeTtl NegativeTtl;
typedef struct _storeNegative storeNegative;
typedef struct _authConfig authConfig;
typedef struct _cacheSwap cacheSwap;
typedef struct _StatHist StatHist;
typedef struct _bwctrl_entry_domain bwctrl_entry_domain;
typedef struct _bwctrl_entry bwctrl_entry;
typedef struct _String String;
typedef struct _MemMeter MemMeter;
typedef struct _MemPoolMeter MemPoolMeter;
typedef struct _MemPool MemPool;
typedef struct _ClientInfo ClientInfo;
typedef struct _cd_guess_stats cd_guess_stats;
typedef struct _CacheDigest CacheDigest;
typedef struct _Version Version;
typedef struct _FwdState FwdState;
typedef struct _FwdServer FwdServer;
typedef struct _helper helper;
typedef struct _helper_stateful statefulhelper;
typedef struct _helper_server helper_server;
typedef struct _helper_stateful_server helper_stateful_server;
typedef struct _helper_request helper_request;
typedef struct _helper_stateful_request helper_stateful_request;
typedef struct _generic_cbdata generic_cbdata;
typedef struct _storeIOState storeIOState;
typedef struct _queued_read queued_read;
typedef struct _queued_write queued_write;
typedef struct _queued_writev queued_writev;
typedef struct _link_list link_list;
typedef struct _storefs_entry storefs_entry_t;
typedef struct _storerepl_entry storerepl_entry_t;
typedef struct _diskd_queue diskd_queue;
typedef struct _Logfile Logfile;
typedef struct _logformat_acl_replace_string logformat_acl_replace_string_t;
typedef struct _logformat_token_table_entry logformat_token_table_entry;
typedef struct _logformat_token logformat_token;
typedef struct _logformat logformat;
typedef struct _fwd_logformat fwd_logformat;
typedef struct _cacheRequestLogEntry cacheRequestLogEntry;
typedef struct _fwd_diag_info FwdDiagInfo;
typedef struct _notification_style_access notification_style_access;
typedef struct _customlog customlog;
typedef struct _percent percent_t;
typedef struct _RemovalPolicy RemovalPolicy;
typedef struct _RemovalPolicyWalker RemovalPolicyWalker;
typedef struct _RemovalPurgeWalker RemovalPurgeWalker;
typedef struct _RemovalMoveWalker RemovalMoveWalker;
typedef struct _RemovalPolicyNode RemovalPolicyNode;
typedef struct _RemovalPolicySettings RemovalPolicySettings;
typedef struct _MoveToHsd MoveToHsd;
typedef struct _errormap errormap;
typedef struct _PeerMonitor PeerMonitor;
typedef struct _mgipaccess_entry mg_IpAccessEntry;
typedef struct _mgstbidaccess_entry mg_StbidAccessEntry;

typedef struct _http_version_t http_version_t;

typedef struct _ipaccess_entry ipaccess_entry;

typedef struct _store_stat_info store_stat_info;
typedef struct _store_persistent_info store_persistent_info;
typedef struct _cpu_info cpu_info;
typedef struct _blkio_info blkio_info;
typedef struct _part_info part_info;
typedef struct _cpu_stat cpu_stat;
typedef struct _blkio_stat blkio_stat;
typedef struct _movideo_anti_comn MovideoAntiCookie;
typedef struct _movideo_m3u8_arg  MovideoM3u8;
typedef struct _stars_china_black_ip Stars_china_anti;
typedef Array sq_stack_t;

typedef struct _qqTrafficLog qqTrafficLog;

/*for qq_new_traffic.c*/
typedef struct _qqTraffic qqTraffic;
typedef struct _qqTrafficLogfile qqTrafficLogfile;
typedef struct _string_acl_list string_acl_list;

typedef struct _accesslog_host accesslog_host;
typedef struct _accesslog_known_host accesslog_known_host;
typedef struct _accesslog_host_table accesslog_host_table;
typedef union _accesslog_host_cfg accesslog_host_cfg;

#if SQUID_SNMP
typedef variable_list *(oid_ParseFn) (variable_list *, snint *);
typedef struct _snmp_request_t snmp_request_t;
#endif

// for 304 rewrite
typedef struct _SubUrl SubUrl;
typedef struct _WaEntry WaEntry;

#if DELAY_POOLS
typedef struct _delayConfig delayConfig;
typedef struct _delaySpecSet delaySpecSet;
typedef struct _delaySpec delaySpec;
#endif

typedef struct _delayConfig2_list delayConfig2_list;
typedef struct _delay_on_antileetch Delay_on_antileetch;
typedef struct _int_acl_list int_acl_list;
typedef struct _time_acl_list time_acl_list;
typedef struct _time_acl_double time_acl_double;
typedef struct _delay_attack_list delay_attack_list;
typedef struct _rate_attack_entry rate_attack_entry;
typedef struct _methodlist methodlist;

typedef struct _rewrite_saveinfo rewrite_saveinfo;
	
typedef void CWCB(int fd, char *, size_t size, int flag, void *data);
typedef void CNCB(int fd, int status, void *);

typedef void FREE(void *);
typedef void CBDUNL(void *);
typedef void FOCB(void *, int fd, int errcode);
typedef void EVH(void *);
typedef void PF(int, void *);

/* disk.c / diskd.c callback typedefs */
typedef void DRCB(int, const char *buf, int size, int errflag, void *data);
/* Disk read CB */
typedef void DWCB(int, int, size_t, void *);	/* disk write CB */
typedef void DOCB(int, int errflag, void *data);	/* disk open CB */
typedef void DCCB(int, int errflag, void *data);	/* disk close CB */
typedef void DUCB(int errflag, void *data);	/* disk unlink CB */
typedef void DTCB(int errflag, void *data);	/* disk trunc CB */

typedef void FQDNH(const char *, void *);
typedef void IDCB(const char *ident, void *data);
typedef void IPH(const ipcache_addrs *, void *);
typedef void IRCB(peer *, peer_t, protocol_t, void *, void *data);
typedef void PSC(FwdServer *, void *);
typedef void RH(void *data, char *);
typedef void UH(void *data, wordlist *);
typedef int DEFER(int fd, void *data);
typedef int READ_HANDLER(int, char *, int);
typedef int WRITE_HANDLER(int, const char *, int);
typedef void CBCB(char *buf, ssize_t size, void *data);
typedef void BODY_HANDLER(request_t * req, char *, size_t, CBCB *, void *);

typedef void STIOCB(void *their_data, int errflag, storeIOState *);
typedef void STFNCB(void *their_data, int errflag, storeIOState *);
typedef void STRCB(void *their_data, const char *buf, ssize_t len);

typedef void SIH(storeIOState *, void *);	/* swap in */
typedef int QS(const void *, const void *);	/* qsort */
typedef void STCB(void *, char *, ssize_t);	/* store callback */
typedef void STABH(void *);
typedef void ERCB(int fd, void *, size_t);
typedef void OBJH(StoreEntry *);
typedef void ActionHandler(StoreEntry *, void *);
typedef void SIGHDLR(int sig);
typedef void STVLDCB(void *, int, int);
typedef void HLPCB(void *, char *buf);
typedef void HLPSCB(void *, void *lastserver, char *buf);
typedef int HLPSAVAIL(void *);
typedef void HLPSRESET(void *);
typedef void HLPCMDOPTS(int *argc, char **argv);
typedef void IDNSCB(void *, rfc1035_rr *, int, const char *);

typedef void STINIT(SwapDir *);
typedef void STCHECKCONFIG(SwapDir *);
typedef void STNEWFS(SwapDir *);
typedef void STDUMP(StoreEntry *, SwapDir *);
typedef void STFREE(SwapDir *);
typedef int STDBLCHECK(SwapDir *, StoreEntry *);
typedef void STSTATFS(SwapDir *, StoreEntry *);
typedef void STMAINTAINFS(SwapDir *);
typedef int STCHECKLOADAV(SwapDir *, store_op_t op);
typedef int STCHECKOBJ(SwapDir *, const StoreEntry *);
typedef void STREFOBJ(SwapDir *, StoreEntry *);
typedef void STUNREFOBJ(SwapDir *, StoreEntry *);
typedef void STSETUP(storefs_entry_t *);
typedef void STDONE(void);
typedef int STCALLBACK(SwapDir *);
typedef void STSYNC(SwapDir *);
typedef void STINDEX(SwapDir *, FILE *);
typedef const char *STPATH(SwapDir *, StoreEntry *);

typedef storeIOState *STOBJCREATE(SwapDir *, StoreEntry *, STFNCB *, STIOCB *, void *);
typedef storeIOState *STOBJOPEN(SwapDir *, StoreEntry *, STFNCB *, STIOCB *, void *);
typedef void STOBJSYNC(SwapDir *, storeIOState *);
typedef void STOBJCLOSE(SwapDir *, storeIOState *);
typedef void STOBJREAD(SwapDir *, storeIOState *, char *, size_t, squid_off_t, STRCB *, void *);
typedef void STOBJWRITE(SwapDir *, storeIOState *, char *, size_t, squid_off_t, FREE *);
typedef void STOBJWRITEV(SwapDir *, storeIOState *, struct iovec *, int, size_t, squid_off_t, void (*)(struct iovec *, int));
typedef void STOBJUNLINK(SwapDir *, StoreEntry *);
typedef void STOBJUNLINKMIN(SwapDir *, StoreEntryMin *);
typedef void STOBJRECYCLE(SwapDir *, StoreEntry *);
typedef StoreEntry *STOBJRELOAD(SwapDir *, StoreEntryMin *);
typedef void STOBJUNLOAD(SwapDir *, StoreEntry *);
typedef StoreEntry *STOBJREADFULL(SwapDir *, StoreEntryMin *);

typedef void STLOGOPEN(SwapDir *);
typedef void STLOGCLOSE(SwapDir *);
typedef void STLOGWRITE(const SwapDir *, const StoreEntry *, int);
typedef void STLOGCACHE(SwapDir *);
typedef int STLOGCLEANSTART(SwapDir *);
typedef const StoreEntry *STLOGCLEANNEXTENTRY(SwapDir *);
typedef void STLOGCLEANWRITE(SwapDir *, const StoreEntry *);
typedef void STLOGCLEANDONE(SwapDir *);

/* Store dir configuration routines */
/* SwapDir *sd, char *path ( + char *opt later when the strtok mess is gone) */
typedef void STFSPARSE(SwapDir *, int, char *);
typedef void STFSRECONFIGURE(SwapDir *, int, char *);
typedef void STFSSTARTUP(void);
typedef void STFSSHUTDOWN(void);

typedef double hbase_f(double);
typedef void StatHistBinDumper(StoreEntry *, int idx, double val, double size, int count);

/* authenticate.c authenticate scheme routines typedefs */
typedef int AUTHSACTIVE(void);
typedef int AUTHSAUTHED(auth_user_request_t *);
typedef void AUTHSAUTHUSER(auth_user_request_t *, request_t *, ConnStateData *, http_hdr_type);
typedef int AUTHSCONFIGURED(void);
typedef void AUTHSDECODE(auth_user_request_t *, const char *);
typedef int AUTHSDIRECTION(auth_user_request_t *);
typedef void AUTHSDUMP(StoreEntry *, const char *, authScheme *);
typedef void AUTHSFIXERR(auth_user_request_t *, HttpReply *, http_hdr_type, request_t *);
typedef void AUTHSADDHEADER(auth_user_request_t *, HttpReply *, int);
typedef void AUTHSADDTRAILER(auth_user_request_t *, HttpReply *, int);
typedef void AUTHSFREE(auth_user_t *);
typedef void AUTHSFREECONFIG(authScheme *);
typedef char *AUTHSUSERNAME(auth_user_t *);
typedef void AUTHSONCLOSEC(ConnStateData *);
typedef void AUTHSPARSE(authScheme *, int, char *);
typedef void AUTHSCHECKCONFIG(authScheme *);
typedef void AUTHSINIT(authScheme *);
typedef void AUTHSREQFREE(auth_user_request_t *);
typedef void AUTHSSETUP(authscheme_entry_t *);
typedef void AUTHSSHUTDOWN(void);
typedef void AUTHSSTART(auth_user_request_t *, RH *, void *);
typedef void AUTHSSTATS(StoreEntry *);
typedef const char *AUTHSCONNLASTHEADER(auth_user_request_t *);

/* append/vprintf's for Packer */
typedef void (*append_f) (void *, const char *buf, size_t size);
#if STDC_HEADERS
typedef void (*vprintf_f) (void *, const char *fmt, va_list args);
#else
typedef void (*vprintf_f) ();
#endif

/* MD5 cache keys */
typedef unsigned char cache_key;

/* context-based debugging, the actual type is subject to change */
typedef int Ctx;

/* in case we want to change it later */
typedef int mb_size_t;

/* iteration for HttpHdrRange */
typedef int HttpHdrRangePos;

/*iteration for headers; use HttpHeaderPos as opaque type, do not interpret */
typedef int HttpHeaderPos;

/* big mask for http headers */
typedef char HttpHeaderMask[(HDR_ENUM_END + 7) / 8];

/* a common objPackInto interface; used by debugObj */
typedef void (*ObjPackMethod) (void *obj, Packer * p);
typedef void AIOCB(int fd, void *cbdata, const char *buf, int aio_return, int aio_errno);
typedef void CompressHandle(clientHttpRequest *, char *, int, AIOCB *, void *);
typedef void CompressHandleState(HttpStateData *, char *, int, AIOCB *, void *);
typedef void DecompressHandleState(void *, char *, int, AIOCB *, void *);
typedef struct _HttpCompress HttpCompress;
typedef struct _HttpDecompress HttpDecompress;
typedef struct _HttpCompressState HttpCompressState;
typedef struct _HttpRangeCompress HttpRangeCompress;

typedef struct _Delta Delta;
typedef struct _Chunk Chunk;

#if DELAY_POOLS
typedef unsigned int delay_id;
#endif

#if USE_HTCP
typedef struct _htcpReplyData htcpReplyData;
#endif

typedef struct _bemgrWriteMemBuf bemgrWriteMemBuf;
typedef struct _bemgr_request bemgr_request;

typedef RemovalPolicy *REMOVALPOLICYCREATE(wordlist * args);

typedef int STDIRSELECT(const StoreEntry *);

// delay reply********************************//

typedef struct _delay_reply delay_reply;

typedef struct _external_acl external_acl;
typedef struct _external_acl_entry external_acl_entry;

typedef void ERRMAPCB(StoreEntry *, int body_offset, squid_off_t content_length, void *data);

typedef struct _VaryData VaryData;
typedef void STLVCB(VaryData * vary, void *cbdata);

typedef struct _PartitionData PartitionData;
typedef struct _ChildrenEntry ChildrenEntry;
typedef struct _ipcache_entry ipcache_entry; 

typedef struct _partitionStoreEntry partitionStoreEntry;
typedef struct _LocateVaryState LocateVaryState;

typedef void STLHCB(download_content_check_t dcc);
typedef int RTHCB(download_content_check_t *dcc);
typedef struct _LocateHashState LocateHashState;
typedef struct _LocateHashState realtimeHashState;

typedef struct _sub_status sub_status;
typedef struct _sub_ip sub_ip;
typedef struct _RequestLogData RequestLogData;
typedef struct _jntv_style jntv_style;
typedef struct _encrypt_ts_rewrite encrypt_ts_rewrite;
typedef struct _http_header_methods http_header_methods;

typedef struct _hntv_hash_entry hntv_hash_entry;
typedef struct _hntv_hash_entry ssport_hash_entry;

typedef struct _winstore_keyid winstore_keyid;
typedef struct _winstore_algorithm winstore_algorithm;
typedef struct _winstore_style winstore_style;
typedef struct _qiniu_private  QiniuPrivate;

/*purge from mem interface*/
typedef struct _uds_conn_state_t uds_conn_state_t;
typedef struct _purge_request_t purge_request_t;
typedef struct _purge_task_t purge_task_t;
typedef struct _purge_work_t purge_work_t;
typedef struct _purge_pool_t purge_pool_t;
typedef struct _purge_state_t purge_state_t;

typedef struct _string_list string_list;
typedef struct _string_node string_node;

typedef struct _vary_item vary_item;

#endif /* SQUID_TYPEDEFS_H */
