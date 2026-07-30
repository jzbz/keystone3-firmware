#include "gui_dcr.h"
#include "gui_chain_components.h"
#include "user_memory.h"
#include "account_manager.h"
#include "account_public_info.h"
#include "gui_chain.h"
#include "keystore.h"
#include "screen_manager.h"

static bool g_isMulti = false;
static URParseResult *g_urResult = NULL;
static URParseMultiResult *g_urMultiResult = NULL;
static void *g_parseResult = NULL;
static DisplayDcrTx *g_dcrData;

#define CHECK_FREE_PARSE_RESULT(result)                                                             \
    if (result != NULL)                                                                             \
    {                                                                                               \
        free_TransactionParseResult_DisplayDcrTx((PtrT_TransactionParseResult_DisplayDcrTx)result); \
        result = NULL;                                                                              \
    }

void GuiSetDcrUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi)
{
    g_urResult = urResult;
    g_urMultiResult = urMultiResult;
    g_isMulti = multi;
}

/// The UR result the active flow is working from, or NULL if there is none.
/// FreeDcrMemory clears both pointers, so a caller that can report failure should
/// check rather than dereference.
static void *DcrUrData(void)
{
    if (g_isMulti) {
        return g_urMultiResult != NULL ? g_urMultiResult->data : NULL;
    }
    return g_urResult != NULL ? g_urResult->data : NULL;
}

void *GuiGetDcrGUIData(void)
{
    CHECK_FREE_PARSE_RESULT(g_parseResult);
    g_dcrData = NULL;
    void *data = DcrUrData();
    if (data == NULL) {
        return NULL;
    }
    char *xPub = GetCurrentAccountPublicKey(XPUB_TYPE_DCR);

    PtrT_TransactionParseResult_DisplayDcrTx parseResult = NULL;
    do {
        parseResult = parse_dcr_tx(data, xPub);
        // Publish the pointer BEFORE the error check. CHECK_CHAIN_BREAK leaves the
        // block on a parse failure, so a store placed after it never runs and the
        // heap result — along with the error string it carries — becomes
        // unreachable. FreeDcrMemory can only release what g_parseResult points at,
        // so on this build the bytes would be lost from the same FreeRTOS heap the
        // UI allocates from, on every failed parse.
        g_parseResult = (void *)parseResult;
        CHECK_CHAIN_BREAK(parseResult);
        g_dcrData = parseResult->data;
    } while (0);
    return g_parseResult;
}

static lv_obj_t *GuiDcrTxItemList(lv_obj_t *parent, const char *title, VecFFI_DisplayDcrTxItem *items, const char *tag, lv_obj_t *last_view);

void GuiDcrTxOverview(lv_obj_t *parent, void *totalData)
{
    // Refuse to render rather than dereference a NULL or freed parse result. This
    // screen is what the user reads before authorising a spend, so a half-built
    // version of it is worse than none.
    if (g_dcrData == NULL) {
        return;
    }

    lv_obj_set_size(parent, 408, 480);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t *container = GuiCreateContainerWithParent(parent, 408, 480);
    lv_obj_add_flag(container, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(container, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t *last_view = NULL;

    // The mislabelled-change warning that used to open this screen is gone. It
    // fired when the companion called an output change and the old bounded address
    // scan could not derive it — which also fired for the user's own change beyond
    // the scan window. Under the version 2 package format an output is change only
    // if a supplied derivation path produces its script, and a path that fails to
    // derive is refused before the review screen is built, so the condition can no
    // longer occur and there is nothing to warn about here.

    last_view = CreateTransactionItemView(container, _("Amount"), g_dcrData->total_send_value, last_view);
    last_view = CreateTransactionItemView(container, _("Fee"), g_dcrData->fee_value, last_view);

    // Shown only when set, so the usual transaction does not carry two rows of
    // zeroes the user learns to skip. Expiry in particular has no Bitcoin analogue:
    // past that height the transaction is permanently invalid, so a companion can
    // hand over something that reviews perfectly and then never confirms. Both
    // fields are attacker-controlled and are committed by the signature, so the
    // device must not sign them out of sight.
    if (g_dcrData->lock_time != NULL) {
        last_view = CreateTransactionItemView(container, _("Lock Time"), g_dcrData->lock_time, last_view);
    }
    if (g_dcrData->expiry != NULL) {
        last_view = CreateTransactionItemView(container, _("Expiry"), g_dcrData->expiry, last_view);
    }

    if (g_dcrData->from != NULL && g_dcrData->from->size > 0) {
        last_view = GuiDcrTxItemList(container, _("From"), g_dcrData->from, NULL, last_view);
    }
    if (g_dcrData->to != NULL && g_dcrData->to->size > 0) {
        last_view = GuiDcrTxItemList(container, _("To"), g_dcrData->to, NULL, last_view);
    }
    if (g_dcrData->change != NULL && g_dcrData->change->size > 0) {
        last_view = GuiDcrTxItemList(container, _("Change"), g_dcrData->change, "Change", last_view);
    }
}

static lv_obj_t *GuiDcrTxItemList(lv_obj_t *parent, const char *title, VecFFI_DisplayDcrTxItem *items, const char *tag, lv_obj_t *last_view)
{
    lv_obj_t *label, *container;
    uint16_t height = 0;

    container = CreateTransactionContentContainer(parent, 408, height);
    if (last_view != NULL) {
        lv_obj_align_to(container, last_view, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 24);
    } else {
        lv_obj_align(container, LV_ALIGN_TOP_LEFT, 0, 0);
    }

    // top padding
    height += 16;

    label = GuiCreateIllustrateLabel(container, title);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, height);
    lv_obj_set_style_text_color(label, WHITE_COLOR, LV_PART_MAIN);
    lv_obj_set_style_text_opa(label, LV_OPA_56, LV_PART_MAIN | LV_STATE_DEFAULT);

    height += 30;

    lv_obj_t *innerContainer;

    for (size_t i = 0; i < items->size; i++) {
        lv_obj_t *valueLabel, *indexLabel, *addressLabel;
        uint16_t innerHeight = 0;
        if (i > 0) {
            //add margin
            innerHeight += 16;
        }
        innerContainer = GuiCreateContainerWithParent(container, 360, innerHeight);
        lv_obj_set_style_bg_opa(innerContainer, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_align(innerContainer, LV_ALIGN_TOP_LEFT, 24, height);

        char order[8] = {0};
        snprintf_s(order, sizeof(order), "#%d", i + 1);
        indexLabel = GuiCreateIllustrateLabel(innerContainer, order);
        lv_obj_align(indexLabel, LV_ALIGN_TOP_LEFT, 0, innerHeight);

        valueLabel = GuiCreateIllustrateLabel(innerContainer, items->data[i].value);
        lv_obj_set_style_text_color(valueLabel, ORANGE_COLOR, LV_PART_MAIN);
        lv_obj_align_to(valueLabel, indexLabel, LV_ALIGN_OUT_RIGHT_MID, 16, 0);

        if (tag != NULL) {
            lv_obj_t *tagContainer = GuiCreateContainerWithParent(innerContainer, 87, 30);
            lv_obj_set_style_radius(tagContainer, 16, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(tagContainer, WHITE_COLOR, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(tagContainer, 30, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_t *tagLabel = lv_label_create(tagContainer);
            lv_label_set_text(tagLabel, tag);
            lv_obj_set_style_text_font(tagLabel, g_defIllustrateFont, LV_PART_MAIN);
            lv_obj_set_style_text_color(tagLabel, WHITE_COLOR, LV_PART_MAIN);
            lv_obj_set_style_text_opa(tagLabel, 163, LV_PART_MAIN);
            lv_obj_align(tagLabel, LV_ALIGN_CENTER, 0, 0);

            lv_obj_align_to(tagContainer, valueLabel, LV_ALIGN_OUT_RIGHT_MID, 16, 0);
        }

        innerHeight += 30;

        addressLabel = GuiCreateIllustrateLabel(innerContainer, items->data[i].address);
        lv_obj_set_width(addressLabel, 360);
        lv_label_set_long_mode(addressLabel, LV_LABEL_LONG_WRAP);
        lv_obj_align(addressLabel, LV_ALIGN_TOP_LEFT, 0, innerHeight);
        lv_obj_update_layout(addressLabel);

        innerHeight += lv_obj_get_height(addressLabel);

        lv_obj_set_height(innerContainer, innerHeight);
        lv_obj_update_layout(innerContainer);

        height += innerHeight;
    }

    // bottom padding
    height += 16;

    lv_obj_set_height(container, height);
    lv_obj_update_layout(container);

    return container;
}

// NOTE: these two deliberately do NOT guard against a NULL UR result, unlike
// GuiGetDcrGUIData above. Returning NULL here would be worse than the deref it
// avoids: ModelTransactionCheckResult in src/ui/gui_model/gui_model.c dereferences
// the result inside its `else` branch without a NULL check, so a NULL return
// crashes there instead. That caller bug is pre-existing, shared by every chain,
// and already reachable through CheckUrResult's own `return NULL` for an unknown
// view type — fixing it belongs in that file, not here. Both functions run only
// after GuiSetDcrUrData has supplied the pointers, matching the idiom every other
// chain uses.
PtrT_TransactionCheckResult GuiGetDcrCheckResult(void)
{
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    char *xPub = GetCurrentAccountPublicKey(XPUB_TYPE_DCR);
    return check_dcr_tx(data, xPub);
}

UREncodeResult *GuiGetDcrSignQrCodeData(void)
{
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    return SignInternal(sign_dcr_tx, data);
}

void FreeDcrMemory(void)
{
    CHECK_FREE_UR_RESULT(g_urResult, false);
    CHECK_FREE_UR_RESULT(g_urMultiResult, true);
    CHECK_FREE_PARSE_RESULT(g_parseResult);
    // g_dcrData points into the parse result just freed. Leaving it set would leave
    // a dangling pointer that GuiDcrTxOverview dereferences without a guard. No
    // current call path reaches the overview after a free, but the cost of not
    // relying on that is one assignment, and the screen in question authorises
    // spends.
    g_dcrData = NULL;
}
