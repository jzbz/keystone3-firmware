#ifndef _GUI_DCR_H
#define _GUI_DCR_H
#include "rust.h"
#include "gui.h"

void GuiSetDcrUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void *GuiGetDcrGUIData(void);
PtrT_TransactionCheckResult GuiGetDcrCheckResult(void);
UREncodeResult *GuiGetDcrSignQrCodeData(void);
void FreeDcrMemory(void);

void GuiDcrTxOverview(lv_obj_t *parent, void *totalData);

#endif
