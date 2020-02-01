/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * Implement JSON/eve logging app-layer MySQL.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-mysql.h"
#include "output-json-mysql.h"

#include "rust.h"
#include "rust-mysql-log-gen.h"

typedef struct LogMysqlFileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} LogMysqlFileCtx;

typedef struct LogMysqlLogThread_ {
    LogMysqlFileCtx *mysqllog_ctx;
    MemBuffer          *buffer;
} LogMysqlLogThread;

json_t *JsonMysqlAddMetadata(const Flow *f, uint64_t tx_id)
{
    MysqlState *state = FlowGetAppState(f);
    if (state) {
        MysqlTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_MYSQL, state, tx_id);
        if (tx) {
            return rs_mysql_log_json(state, tx);
        }
    }

    return NULL;
}

static int JsonMysqlLogger(ThreadVars *tv, void *thread_data,
                         const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    MysqlTransaction *mysqltx = tx;
    LogMysqlLogThread *thread = thread_data;
    json_t *js, *mysqljs;

    js = CreateJSONHeader(p, LOG_DIR_PACKET, "mysql");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    JsonAddCommonOptions(&thread->mysqllog_ctx->cfg, p, f, js);

    mysqljs = rs_mysql_log_json(state, mysqltx);
    if (unlikely(mysqljs == NULL)) {
        goto error;
    }
    json_object_set_new(js, "mysql", mysqljs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->mysqllog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;

    error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputMysqlLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogMysqlFileCtx *mysqllog_ctx = (LogMysqlFileCtx *)output_ctx->data;
    SCFree(mysqllog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputMysqlLogInitSub(ConfNode *conf,
                                            OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogMysqlFileCtx *mysqllog_ctx = SCCalloc(1, sizeof(*mysqllog_ctx));
    if (unlikely(mysqllog_ctx == NULL)) {
        return result;
    }
    mysqllog_ctx->file_ctx = ajt->file_ctx;
    mysqllog_ctx->cfg = ajt->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(mysqllog_ctx);
        return result;
    }
    output_ctx->data = mysqllog_ctx;
    output_ctx->DeInit = OutputMysqlLogDeInitCtxSub;

    SCLogDebug("MySQL log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MYSQL);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonMysqlLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogMysqlLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogMysql.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->mysqllog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonMysqlLogThreadDeinit(ThreadVars *t, void *data)
{
    LogMysqlLogThread *thread = (LogMysqlLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonMysqlLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_MYSQL, "eve-log", "JsonMysqlLog",
                              "eve-log.mysql", OutputMysqlLogInitSub, ALPROTO_MYSQL,
                              JsonMysqlLogger, JsonMysqlLogThreadInit,
                              JsonMysqlLogThreadDeinit, NULL);

    SCLogDebug("MySQL JSON logger registered.");
}
