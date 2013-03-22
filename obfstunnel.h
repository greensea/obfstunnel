#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OT_LOG(__fmt, ...)	fprintf(stderr, __fmt, ##__VA_ARGS__)
#define OT_LOGE	OT_LOG
#define OT_LOGW	OT_LOG
#define OT_LOGD	OT_LOG
#define OT_LOGI	OT_LOG


#define OT_SIDE_SERVER	1
#define OT_SIDE_CLIENT	2
#define OT_DEFAULT_PORT	1234
#define OT_PACKET_SIZE	18000	/// Max packet size for obfstunnel packet
