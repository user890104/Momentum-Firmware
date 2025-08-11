#include "vw_2.h"

#include <lib/flipper_format/flipper_format_i.h>
#include <lib/toolbox/manchester_decoder.h>
#include <lib/toolbox/manchester_encoder.h>
#include <lib/toolbox/stream/stream.h>

#include "../blocks/const.h"
#include "../blocks/decoder.h"
#include "../blocks/encoder.h"
#include "../blocks/generic.h"
#include "../blocks/math.h"

// https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_garcia.pdf

#define TAG "SubGhzProtocolVw2"
#define TYPE 0xC0

static const SubGhzBlockConst subghz_protocol_vw_2_const = {
    .te_short = 500,
    .te_long = 1000,
    .te_delta = 120,
    .min_count_bit_for_found = 80,
};

struct SubGhzProtocolDecoderVw2 {
    SubGhzProtocolDecoderBase base;

    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_saved_state;

    uint8_t data[10];
    uint8_t type;
};

struct SubGhzProtocolEncoderVw2 {
    SubGhzProtocolEncoderBase base;

    SubGhzProtocolBlockEncoder encoder;
    SubGhzBlockGeneric generic;

    uint8_t data[10];
};

typedef enum {
    Vw2DecoderStepReset = 0,
    Vw2DecoderStepFoundSync,
    Vw2DecoderStepFoundStart1,
    Vw2DecoderStepFoundStart2,
    Vw2DecoderStepFoundStart3,
    Vw2DecoderStepFoundData,
} Vw2DecoderStep;

const SubGhzProtocolDecoder subghz_protocol_vw_2_decoder = {
    .alloc = subghz_protocol_decoder_vw_2_alloc,
    .free = subghz_protocol_decoder_vw_2_free,

    .feed = subghz_protocol_decoder_vw_2_feed,
    .reset = subghz_protocol_decoder_vw_2_reset,

    .get_hash_data = NULL,
    .get_hash_data_long = subghz_protocol_decoder_vw_2_get_hash_data,
    .serialize = subghz_protocol_decoder_vw_2_serialize,
    .deserialize = subghz_protocol_decoder_vw_2_deserialize,
    .get_string = subghz_protocol_decoder_vw_2_get_string,
    .get_string_brief = subghz_protocol_decoder_vw_2_get_string_brief,
};

const SubGhzProtocolEncoder subghz_protocol_vw_2_encoder = {
    .alloc = subghz_protocol_encoder_vw_2_alloc,
    .free = subghz_protocol_encoder_vw_2_free,

    .deserialize = subghz_protocol_encoder_vw_2_deserialize,
    .stop = subghz_protocol_encoder_vw_2_stop,
    .yield = subghz_protocol_encoder_vw_2_yield,
};

const SubGhzProtocol subghz_protocol_vw_2 = {
    .name = SUBGHZ_PROTOCOL_VW_2_NAME,
    .type = SubGhzProtocolTypeDynamic,
    .flag = SubGhzProtocolFlag_433 | SubGhzProtocolFlag_AM | SubGhzProtocolFlag_Decodable |
            SubGhzProtocolFlag_Load | SubGhzProtocolFlag_Save | SubGhzProtocolFlag_Send,    
    .decoder = &subghz_protocol_vw_2_decoder,
    .encoder = &subghz_protocol_vw_2_encoder,

    .filter = SubGhzProtocolFilter_Cars,
};

// there is a problem with the function in lib/toolbox/manchester_decoder, so it is reimplemented
// thanks to CodeAllNight (https://github.com/jamisonderek) for sharing his fixed version
static const ManchesterState manchester_reset_state = ManchesterStateMid1;

bool subghz_protocol_encoder_vw_2_manchester_advance(
    ManchesterState state,
    ManchesterEvent event,
    ManchesterState* next_state,
    bool* data) {
    bool result = false;
    ManchesterState new_state = manchester_reset_state;

    if(event == ManchesterEventReset) {
        new_state = manchester_reset_state;
    } else if(state == ManchesterStateMid0 || state == ManchesterStateMid1) {
        if(event == ManchesterEventShortHigh) {
            new_state = ManchesterStateStart1;
        } else if(event == ManchesterEventShortLow) {
            new_state = ManchesterStateStart0;
        } else {
            new_state = manchester_reset_state;
        }
    } else if(state == ManchesterStateStart1) {
        if(event == ManchesterEventShortLow) {
            new_state = ManchesterStateMid1;
            result = true;
            if(data) *data = true;
        } else if(event == ManchesterEventLongLow) {
            new_state = ManchesterStateStart0;
            result = true;
            if(data) *data = true;
        } else {
            new_state = manchester_reset_state;
        }
    } else if(state == ManchesterStateStart0) {
        if(event == ManchesterEventShortHigh) {
            new_state = ManchesterStateMid0;
            result = true;
            if(data) *data = false;
        } else if(event == ManchesterEventLongHigh) {
            new_state = ManchesterStateStart1;
            result = true;
            if(data) *data = false;
        } else {
            new_state = manchester_reset_state;
        }
    }

    *next_state = new_state;
    return result;
}

/**
 * Calculates the next LevelDuration in an upload
 * @param result ManchesterEncoderResult
 * @return LevelDuration
 */
static LevelDuration
    subghz_protocol_encoder_vw_2_add_duration_to_upload(ManchesterEncoderResult result);

/**
 * Add the next bit to the decoding result
 * @param instance Pointer to a SubGhzProtocolDecoderVw2 instance
 * @param level Level of the next bit
 */
static void subghz_protocol_decoder_vw_2_add_bit(SubGhzProtocolDecoderVw2* instance, bool level);

/**
 * Parses the raw data into separate fields
 * @param instance Pointer to a SubGhzProtocolDecoderVw2 instance
 */
static void subghz_protocol_vw_2_parse_data(SubGhzProtocolDecoderVw2* instance);

void* subghz_protocol_encoder_vw_2_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolEncoderVw2* instance = malloc(sizeof(SubGhzProtocolEncoderVw2));

    instance->base.protocol = &subghz_protocol_vw_2;
    instance->generic.protocol_name = instance->base.protocol->name;

    instance->encoder.repeat = 1;
    instance->encoder.size_upload =
        43 * 2 + 2 + 3 * 2 + subghz_protocol_vw_2_const.min_count_bit_for_found * 2 + 1;
    instance->encoder.upload = malloc(instance->encoder.size_upload * sizeof(LevelDuration));
    instance->encoder.is_running = false;
    return instance;
}

void subghz_protocol_encoder_vw_2_free(void* context) {
    furi_assert(context);
    SubGhzProtocolEncoderVw2* instance = context;
    free(instance->encoder.upload);
    free(instance);
}

/**
 * Generating an upload from data.
 * @param instance Pointer to a SubGhzProtocolEncoderVw2 instance
 * @return true On success
 */
static bool subghz_protocol_encoder_vw_2_get_upload(SubGhzProtocolEncoderVw2* instance) {
    furi_assert(instance);
    size_t index = 0;
    ManchesterEncoderState enc_state;
    manchester_encoder_reset(&enc_state);
    ManchesterEncoderResult result;

    uint32_t duration_short = (uint32_t)subghz_protocol_vw_2_const.te_short;
    uint32_t duration_long = (uint32_t)subghz_protocol_vw_2_const.te_long;
    uint32_t duration_med = (duration_long + duration_short) / 2;

    // Send sync
    for(uint8_t i = 0; i < 43; i++) {
        instance->encoder.upload[index++] = level_duration_make(true, duration_short);
        instance->encoder.upload[index++] = level_duration_make(false, duration_short);
    }

    instance->encoder.upload[index++] = level_duration_make(true, duration_long);
    instance->encoder.upload[index++] = level_duration_make(false, duration_short);
    
    for(uint8_t i = 0; i < 2; i++) {
        instance->encoder.upload[index++] = level_duration_make(true, duration_med);
        instance->encoder.upload[index++] = level_duration_make(false, duration_med);
    }

    // Send key data
    uint8_t max_byte_index = instance->generic.data_count_bit / 8 - 1;

    for(uint8_t i = instance->generic.data_count_bit; i > 0; i--) {
        uint8_t bit_index = i - 1;
        uint8_t byte_index = max_byte_index - bit_index / 8;
        bool bit_is_set = !bit_read(instance->data[byte_index], bit_index & 0x07);

        if(!manchester_encoder_advance(&enc_state, bit_is_set, &result)) {
            instance->encoder.upload[index++] =
                subghz_protocol_encoder_vw_2_add_duration_to_upload(result);
            manchester_encoder_advance(&enc_state, bit_is_set, &result);
        }

        instance->encoder.upload[index++] =
            subghz_protocol_encoder_vw_2_add_duration_to_upload(result);
    }

    instance->encoder.upload[index++] =
        subghz_protocol_encoder_vw_2_add_duration_to_upload(manchester_encoder_finish(&enc_state));

    instance->encoder.upload[index++] = level_duration_make(false, duration_short);

    instance->encoder.size_upload = index;

    return true;
}

SubGhzProtocolStatus
    subghz_protocol_encoder_vw_2_deserialize(void* context, FlipperFormat* flipper_format) {
    furi_assert(context);
    SubGhzProtocolEncoderVw2* instance = context;

    SubGhzProtocolStatus ret =
        subghz_block_generic_deserialize(&instance->generic, flipper_format);
    if(ret != SubGhzProtocolStatusOk) {
        return ret;
    }

    // Generic key is too small, so we reset it and rewind to get real, longer, data
    instance->generic.data = 0;

    if(instance->generic.data_count_bit !=
       subghz_protocol_vw_2_const.min_count_bit_for_found) {
        FURI_LOG_E(TAG, "Wrong number of bits in key");
        return SubGhzProtocolStatusErrorValueBitCount;
       }

    if(!flipper_format_rewind(flipper_format)) {
        FURI_LOG_E(TAG, "Rewind error");
        return SubGhzProtocolStatusErrorParserOthers;
    }

    size_t key_length = instance->generic.data_count_bit / 8;

    if(!flipper_format_read_hex(flipper_format, "Key", instance->data, key_length)) {
        FURI_LOG_E(TAG, "Unable to read Key in encoder");
        return SubGhzProtocolStatusErrorParserKey;
    }

    // optional parameter
    flipper_format_read_uint32(flipper_format, "Repeat", (uint32_t*)&instance->encoder.repeat, 1);

    if(!subghz_protocol_encoder_vw_2_get_upload(instance)) {
        return SubGhzProtocolStatusErrorEncoderGetUpload;
    }

    instance->encoder.is_running = true;

    return SubGhzProtocolStatusOk;
}

void subghz_protocol_encoder_vw_2_stop(void* context) {
    SubGhzProtocolEncoderVw2* instance = context;
    instance->encoder.is_running = false;
}

LevelDuration subghz_protocol_encoder_vw_2_yield(void* context) {
    SubGhzProtocolEncoderVw2* instance = context;

    if(instance->encoder.repeat == 0 || !instance->encoder.is_running) {
        instance->encoder.is_running = false;
        return level_duration_reset();
    }

    LevelDuration ret = instance->encoder.upload[instance->encoder.front];

    if(++instance->encoder.front == instance->encoder.size_upload) {
        instance->encoder.repeat--;
        instance->encoder.front = 0;
    }

    return ret;
}

void* subghz_protocol_decoder_vw_2_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolDecoderVw2* instance = malloc(sizeof(SubGhzProtocolDecoderVw2));
    instance->base.protocol = &subghz_protocol_vw_2;
    instance->generic.protocol_name = instance->base.protocol->name;
    return instance;
}

void subghz_protocol_decoder_vw_2_free(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;
    free(instance);
}

void subghz_protocol_decoder_vw_2_reset(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;
    instance->decoder.parser_step = Vw2DecoderStepReset;
    memset(instance->data, 0, 10);
    instance->generic.data_count_bit = 0;
    instance->manchester_saved_state = 0;
}

void subghz_protocol_decoder_vw_2_feed(void* context, bool level, uint32_t duration) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;

    uint32_t duration_short = (uint32_t)subghz_protocol_vw_2_const.te_short;
    uint32_t duration_long = (uint32_t)subghz_protocol_vw_2_const.te_long;
    uint32_t duration_delta = (uint32_t)subghz_protocol_vw_2_const.te_delta;
    uint32_t duration_med = (duration_long + duration_short) / 2;
    uint32_t duration_end = duration_long * 5;

    ManchesterEvent event = ManchesterEventReset;

    switch(instance->decoder.parser_step) {
    case Vw2DecoderStepReset:
        if(DURATION_DIFF(duration, duration_short) < duration_delta) {
            instance->decoder.parser_step = Vw2DecoderStepFoundSync;
        }
        break;
    case Vw2DecoderStepFoundSync:
        if(DURATION_DIFF(duration, duration_short) < duration_delta) {
            // stay on the same step, the pattern repeats about 43 times
            break;
        }

        if(level && DURATION_DIFF(duration, duration_long) < duration_delta) {
            instance->decoder.parser_step = Vw2DecoderStepFoundStart1;
            break;
        }

        instance->decoder.parser_step = Vw2DecoderStepReset;
        break;
    case Vw2DecoderStepFoundStart1:
        if(!level && DURATION_DIFF(duration, duration_short) < duration_delta) {
            instance->decoder.parser_step = Vw2DecoderStepFoundStart2;
            break;
        }

        instance->decoder.parser_step = Vw2DecoderStepReset;
        break;
    case Vw2DecoderStepFoundStart2:
        if(level && DURATION_DIFF(duration, duration_med) < duration_delta) {
            instance->decoder.parser_step = Vw2DecoderStepFoundStart3;
            break;
        }

        instance->decoder.parser_step = Vw2DecoderStepReset;
        break;
    case Vw2DecoderStepFoundStart3:
        if(DURATION_DIFF(duration, duration_med) < duration_delta) {
            // stay on the same step, the pattern repeats 6 times (3 pairs of high/low med)
            break;
        }

        if(level && DURATION_DIFF(duration, duration_short) < duration_delta) {
            subghz_protocol_encoder_vw_2_manchester_advance(
                instance->manchester_saved_state,
                ManchesterEventReset,
                &instance->manchester_saved_state,
                NULL);
            subghz_protocol_encoder_vw_2_manchester_advance(
                instance->manchester_saved_state,
                ManchesterEventShortHigh,
                &instance->manchester_saved_state,
                NULL);
            instance->decoder.parser_step = Vw2DecoderStepFoundData;
            break;
        }

        instance->decoder.parser_step = Vw2DecoderStepReset;
        break;
    case Vw2DecoderStepFoundData:
        if(DURATION_DIFF(duration, duration_short) < duration_delta) {
            event = level ? ManchesterEventShortHigh : ManchesterEventShortLow;
        }

        if(DURATION_DIFF(duration, duration_long) < duration_delta) {
            event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        }

        // the last bit can be arbitrary long, but it is parsed as a short
        if(instance->generic.data_count_bit ==
               subghz_protocol_vw_2_const.min_count_bit_for_found - 1 &&
           !level && duration > duration_end) {
            event = ManchesterEventShortLow;
        }

        if(event == ManchesterEventReset) {
            subghz_protocol_decoder_vw_2_reset(instance);
        } else {
            bool new_level;

            if(subghz_protocol_encoder_vw_2_manchester_advance(
                   instance->manchester_saved_state,
                   event,
                   &instance->manchester_saved_state,
                   &new_level)) {
                subghz_protocol_decoder_vw_2_add_bit(instance, new_level);
            }
        }
        break;
    }
}

uint32_t subghz_protocol_decoder_vw_2_get_hash_data(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;

    union {
        uint32_t full;
        uint8_t split[4];
    } hash = {0};
    size_t key_length = instance->generic.data_count_bit / 8;

    for(size_t i = 0; i < key_length; i++) {
        hash.split[i % sizeof(hash)] ^= instance->data[i];
    }

    return hash.full;
}

SubGhzProtocolStatus subghz_protocol_decoder_vw_2_serialize(
    void* context,
    FlipperFormat* flipper_format,
    SubGhzRadioPreset* preset) {
    furi_assert(context);

    SubGhzProtocolDecoderVw2* instance = context;
    SubGhzProtocolStatus res = SubGhzProtocolStatusError;

    do {
        res = subghz_block_generic_serialize(&instance->generic, flipper_format, preset);
        if(res != SubGhzProtocolStatusOk) {
            break;
        }

        // Generic key is too small, so it writes empty and we update here with real, longer, data
        if(!flipper_format_rewind(flipper_format)) {
            FURI_LOG_E(TAG, "Rewind error");
            res = SubGhzProtocolStatusErrorParserOthers;
            break;
        }

        uint16_t key_length = instance->generic.data_count_bit / 8;

        if(!flipper_format_update_hex(flipper_format, "Key", instance->data, key_length)) {
            FURI_LOG_E(TAG, "Unable to update Key");
            res = SubGhzProtocolStatusErrorParserKey;
            break;
        }
    } while(false);

    return res;
}

SubGhzProtocolStatus
    subghz_protocol_decoder_vw_2_deserialize(void* context, FlipperFormat* flipper_format) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;

    SubGhzProtocolStatus ret =
        subghz_block_generic_deserialize(&instance->generic, flipper_format);
    if(ret != SubGhzProtocolStatusOk) {
        return ret;
    }

    // Generic key is too small, so we reset it and rewind to get real, longer, data
    instance->generic.data = 0;

    if(instance->generic.data_count_bit !=
       subghz_protocol_vw_2_const.min_count_bit_for_found) {
        FURI_LOG_E(TAG, "Wrong number of bits in key");
        return SubGhzProtocolStatusErrorValueBitCount;
       }

    if(!flipper_format_rewind(flipper_format)) {
        FURI_LOG_E(TAG, "Rewind error");
        return SubGhzProtocolStatusErrorParserOthers;
    }

    size_t key_length = instance->generic.data_count_bit / 8;

    if(!flipper_format_read_hex(flipper_format, "Key", instance->data, key_length)) {
        FURI_LOG_E(TAG, "Unable to read Key in decoder");
        return SubGhzProtocolStatusErrorParserKey;
    }

    subghz_protocol_vw_2_parse_data(instance);

    return SubGhzProtocolStatusOk;
}

// 0b0001xxxx = Unlock
// 0b0010xxxx = Lock
// 0b0100xxxx = Trunk
const char *subghz_protocol_vw_2_buttons[] = {
    "None",
    "Unlock",
    "Lock",
    "Un+Lk",
    "Trunk",
    "Un+Tr",
    "Lk+Tr",
    "Un+Lk+Tr",
};

static const char* subghz_protocol_vw_2_get_name_button(uint8_t btn) {
    return subghz_protocol_vw_2_buttons[btn >> 4];
}

void subghz_protocol_decoder_vw_2_get_string(void* context, FuriString* output) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;

    furi_string_cat_printf(
        output,
        "%s %dbit\r\n"
        "Type:0x%02X Btn:%s\r\n"
        "Key:%016llX\r\n",
        instance->generic.protocol_name, instance->generic.data_count_bit,
        instance->type,
        subghz_protocol_vw_2_get_name_button(instance->generic.btn),
        instance->generic.data);
}

void subghz_protocol_decoder_vw_2_get_string_brief(void* context, FuriString* output) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;
    subghz_protocol_vw_2_parse_data(instance);

    uint8_t data_hash = subghz_protocol_blocks_xor_bytes(
        (const uint8_t*)&instance->generic.data, sizeof(uint64_t));
    
    furi_string_cat_printf(
        output,
        "%s %s %02X",
        instance->generic.protocol_name,
        subghz_protocol_vw_2_get_name_button(instance->generic.btn),
        data_hash);
}

static LevelDuration
    subghz_protocol_encoder_vw_2_add_duration_to_upload(ManchesterEncoderResult result) {
    LevelDuration data = {.duration = 0, .level = 0};

    switch(result) {
    case ManchesterEncoderResultShortLow:
        data.duration = subghz_protocol_vw_2_const.te_short;
        data.level = false;
        break;
    case ManchesterEncoderResultLongLow:
        data.duration = subghz_protocol_vw_2_const.te_long;
        data.level = false;
        break;
    case ManchesterEncoderResultLongHigh:
        data.duration = subghz_protocol_vw_2_const.te_long;
        data.level = true;
        break;
    case ManchesterEncoderResultShortHigh:
        data.duration = subghz_protocol_vw_2_const.te_short;
        data.level = true;
        break;

    default:
        furi_crash("SubGhz: ManchesterEncoderResult is incorrect.");
        break;
    }

    return level_duration_make(data.level, data.duration);
}

static void subghz_protocol_vw_2_parse_data(SubGhzProtocolDecoderVw2* instance) {
    furi_assert(instance);

    instance->type = instance->data[0];

    instance->generic.data = 0;

    for(uint8_t i = 1; i < 9; i++) {
        instance->generic.data = instance->generic.data << 8 | instance->data[i];
    }

    instance->generic.btn = instance->data[9];
}

static void subghz_protocol_decoder_vw_2_add_bit(SubGhzProtocolDecoderVw2* instance, bool level) {
    furi_assert(instance);

    if(instance->generic.data_count_bit >= subghz_protocol_vw_2_const.min_count_bit_for_found) {
        return;
    }

    if(level) {
        uint8_t byte_index = instance->generic.data_count_bit / 8;
        uint8_t bit_index = instance->generic.data_count_bit % 8;

        instance->data[byte_index] |= 1 << (7 - bit_index);
    }

    instance->generic.data_count_bit++;

    if(instance->generic.data_count_bit >= subghz_protocol_vw_2_const.min_count_bit_for_found) {
        if (instance->data[0] != TYPE) {
            // unsupported type, discard for now
            FURI_LOG_W(TAG, "Unsupported type 0x%02X", instance->data[0]);
            return;
        }
        
        if(instance->base.callback) {
            instance->base.callback(&instance->base, instance->base.context);
        } else {
            subghz_protocol_decoder_vw_2_reset(instance);
        }
    }
}
