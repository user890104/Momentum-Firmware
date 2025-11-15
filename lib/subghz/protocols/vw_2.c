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
#include "../blocks/custom_btn_i.h"

// https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_garcia.pdf

/*
 * AUT64 algorithm, 12 rounds
 * 8 bytes block size, 8 bytes key size
 * 8 bytes pbox size, 16 bytes sbox size
 * 
 * Based on: Reference AUT64 implementation in JavaScript (aut64.js)
 * Vencislav Atanasov, 2025-09-13
 * 
 * Based on: Reference AUT64 implementation in python
 * C Hicks, hkscy.org, 03-01-19
 */

static const uint8_t table_ln[AUT64_NUM_ROUNDS][8] = {
    { 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3, }, // Round 0
    { 0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2, }, // Round 1
    { 0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1, }, // Round 2
    { 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, }, // Round 3
    { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, }, // Round 4
    { 0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6, }, // Round 5
    { 0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5, }, // Round 6
    { 0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4, }, // Round 7
    { 0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2, }, // Round 8
    { 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3, }, // Round 9
    { 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, }, // Round 10
    { 0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1, }, // Round 11
};

static const uint8_t table_un[AUT64_NUM_ROUNDS][8] = {
    { 0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6, }, // Round 0
    { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, }, // Round 1
    { 0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4, }, // Round 2
    { 0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5, }, // Round 3
    { 0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2, }, // Round 4
    { 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3, }, // Round 5
    { 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, }, // Round 6
    { 0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1, }, // Round 7
    { 0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4, }, // Round 8
    { 0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5, }, // Round 9
    { 0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6, }, // Round 10
    { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, }, // Round 11
};

static const uint8_t table_offset[256] = {
// 0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0
  0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, // 1
  0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD, // 2
  0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2, // 3
  0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9, // 4
  0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6, // 5
  0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4, // 6
  0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB, // 7
  0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1, // 8
  0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE, // 9
  0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC, // A
  0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3, // B
  0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8, // C
  0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7, // D
  0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5, // E
  0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA  // F
};

static const uint8_t table_sub[16] = {
    0x0, 0x1, 0x9, 0xE,
    0xD, 0xB, 0x7, 0x6,
    0xF, 0x2, 0xC, 0x5,
    0xA, 0x4, 0x3, 0x8,
};

static uint8_t key_nibble(const struct aut64_key key, const uint8_t nibble, const uint8_t table[], const uint8_t iteration) {
    const uint8_t keyValue = key.key[table[iteration]];
    const uint8_t offset = (keyValue << 4) | nibble;
    return table_offset[offset];
}

static uint8_t round_key(const struct aut64_key key, const uint8_t state[], const uint8_t roundN) {
    uint8_t result_hi = 0, result_lo = 0;

    for (uint8_t i = 0; i < AUT64_BLOCK_SIZE - 1; i++) {
        result_hi ^= key_nibble(key, state[i] >> 4, table_un[roundN], i);
        result_lo ^= key_nibble(key, state[i] & 0x0F, table_ln[roundN], i);
    }

    return (result_hi << 4) | result_lo;
}

static uint8_t final_byte_nibble(const struct aut64_key key, const uint8_t table[]) {
    const uint8_t keyValue = key.key[table[AUT64_BLOCK_SIZE - 1]];
    return table_sub[keyValue] << 4;
}

static uint8_t encrypt_final_byte_nibble(const struct aut64_key key, const uint8_t nibble, const uint8_t table[]) {
    const uint8_t offset = final_byte_nibble(key, table);
    
    for (uint8_t i = 0; i < 16; i++) {
        if (table_offset[offset + i] == nibble) {
            return i;
        }
    }

    return 0; // should never be reached
}

static uint8_t encrypt_compress(const struct aut64_key key, const uint8_t state[], const uint8_t roundN) {
    const uint8_t roundKey = round_key(key, state, roundN);
    uint8_t result_hi = roundKey >> 4, result_lo = roundKey & 0x0F;
    
    result_hi ^= encrypt_final_byte_nibble(key, state[AUT64_BLOCK_SIZE - 1] >> 4, table_un[roundN]);
    result_lo ^= encrypt_final_byte_nibble(key, state[AUT64_BLOCK_SIZE - 1] & 0x0F, table_ln[roundN]);

    return (result_hi << 4) | result_lo;
}

static uint8_t decrypt_final_byte_nibble(const struct aut64_key key, const uint8_t nibble, const uint8_t table[], const uint8_t result) {
    const uint8_t offset = final_byte_nibble(key, table);

    return table_offset[(result ^ nibble) + offset];
}

static uint8_t decrypt_compress(const struct aut64_key key, const uint8_t state[], const uint8_t roundN) {
    const uint8_t roundKey = round_key(key, state, roundN);
    uint8_t result_hi = roundKey >> 4, result_lo = roundKey & 0x0F;

    result_hi = decrypt_final_byte_nibble(key, state[AUT64_BLOCK_SIZE - 1] >> 4, table_un[roundN], result_hi);
    result_lo = decrypt_final_byte_nibble(key, state[AUT64_BLOCK_SIZE - 1] & 0x0F, table_ln[roundN], result_lo);

    return (result_hi << 4) | result_lo;
}

static uint8_t substitute(const struct aut64_key key, const uint8_t byte) {
    return (key.sbox[byte >> 4] << 4) | key.sbox[byte & 0x0F];
}

static void permute_bytes(const struct aut64_key key, uint8_t state[]) {
    uint8_t result[AUT64_PBOX_SIZE] = { 0 };
    
    for (uint8_t i = 0; i < AUT64_PBOX_SIZE; i++) {
        result[key.pbox[i]] = state[i];
    }

    memcpy(state, result, AUT64_PBOX_SIZE);
}

static uint8_t permute_bits(const struct aut64_key key, const uint8_t byte) {
    uint8_t result = 0;

    for (uint8_t i = 0; i < 8; i++) {
        if (byte & (1 << i)) {
            result |= (1 << key.pbox[i]);
        }
    }

    return result;
}

static void reverse_box(uint8_t *reversed, const uint8_t *box, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        for (size_t j = 0; j < len; j++) {
            if (box[j] == i) {
                reversed[i] = j;
                break;
            }
        }
    }
}

void aut64_encrypt(const struct aut64_key key, uint8_t message[]) {
    struct aut64_key reverse_key;
    memcpy(reverse_key.key, key.key, AUT64_KEY_SIZE);
    reverse_box(reverse_key.pbox, key.pbox, AUT64_PBOX_SIZE);
    reverse_box(reverse_key.sbox, key.sbox, AUT64_SBOX_SIZE);

    for (uint8_t i = 0; i < AUT64_NUM_ROUNDS; i++) {
        permute_bytes(reverse_key, message);
        message[7] = encrypt_compress(reverse_key, message, i);
        message[7] = substitute(reverse_key, message[7]);
        message[7] = permute_bits(reverse_key, message[7]);
        message[7] = substitute(reverse_key, message[7]);
    }
}

void aut64_decrypt(const struct aut64_key key, uint8_t message[]) {
    for (int8_t i = AUT64_NUM_ROUNDS - 1; i >= 0; i--) {
        message[7] = substitute(key, message[7]);
        message[7] = permute_bits(key, message[7]);
        message[7] = substitute(key, message[7]);
        message[7] = decrypt_compress(key, message, i);
        permute_bytes(key, message);
    }
}

#define TAG "SubGhzProtocolVw2"

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

// Key goes here
const struct aut64_key key = {
    .key = { 0 },
    .pbox = { 0 },
    .sbox = { 0 },
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
 * @param generic Pointer to a SubGhzBlockGeneric instance
 * @param data Pointer to uint8_t[10] (encrypted data)
 */
static void subghz_protocol_vw_2_decode_data(SubGhzBlockGeneric* generic, const uint8_t* data);

/**
 * Combines the fields into raw data
 * @param generic Pointer to a SubGhzBlockGeneric instance
 * @param data Pointer to uint8_t[10] (encrypted data)
 */
static void subghz_protocol_vw_2_encode_data(SubGhzBlockGeneric* generic, uint8_t* data);

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

// Get custom button code
static uint8_t subghz_protocol_encoder_vw_2_get_btn_code(void) {
    uint8_t custom_btn_id = subghz_custom_btn_get();
    uint8_t original_btn_code = subghz_custom_btn_get_original();
    uint8_t btn = original_btn_code;

    // Set custom button
    if((custom_btn_id == SUBGHZ_CUSTOM_BTN_OK) && (original_btn_code != 0)) {
        // Restore original button code
        btn = original_btn_code;
    } else if(custom_btn_id == SUBGHZ_CUSTOM_BTN_UP) {
        btn = 0x1; // Unlock
    } else if(custom_btn_id == SUBGHZ_CUSTOM_BTN_DOWN) {
        btn = 0x2; // Lock
    } else if(custom_btn_id == SUBGHZ_CUSTOM_BTN_LEFT) {
        btn = 0x4; // Trunk
    } else if(custom_btn_id == SUBGHZ_CUSTOM_BTN_RIGHT) {
        btn = 0x8; // Panic
    }

    return btn;
}

/**
 * Generating an upload from data.
 * @param instance Pointer to a SubGhzProtocolEncoderVw2 instance
 * @return true On success
 */
static bool subghz_protocol_encoder_vw_2_get_upload(SubGhzProtocolEncoderVw2* instance) {
    furi_assert(instance);
    size_t index = 0;
    
    subghz_protocol_vw_2_decode_data(&instance->generic, instance->data);

    // Save original button for later use
    if (subghz_custom_btn_get_original() == 0) {
        subghz_custom_btn_set_original(instance->generic.btn);
    }
    
    instance->generic.btn = subghz_protocol_encoder_vw_2_get_btn_code();

    int cnt_increment = furi_hal_subghz_get_rolling_counter_mult();
    
    if (instance->generic.cnt + cnt_increment < 0xFFFFFF) {
        instance->generic.cnt += cnt_increment;
    } else {
        instance->generic.cnt = 0;
    }
    
    subghz_protocol_vw_2_encode_data(&instance->generic, instance->data);
    
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

    if(!flipper_format_update_hex(flipper_format, "Key", instance->data, key_length)) {
        FURI_LOG_E(TAG, "Unable to update Key");
        return SubGhzProtocolStatusErrorParserKey;
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

    subghz_protocol_vw_2_decode_data(&instance->generic, instance->data);

    return SubGhzProtocolStatusOk;
}

/*
 * 0b0001xxxx = Unlock
 * 0b0010xxxx = Lock
 * 0b0100xxxx = Trunk
 * 0b1000xxxx = Panic (US only)
 * 
 * It's highly unusual that someone presses more than one button at a time.
 * This is very difficult as they need to be pressed at the exact same moment
 * for the keyfob to actually generate a multi-button packet. Otherwise it's
 * only transmitting the button which got pressed first. But if you manage
 * to do it correctly, a multi-button packet can be received and decoded.
 * It is untested how the car reacts to it.
 */
const char *subghz_protocol_vw_2_buttons[] = {
    "None",
    "Unlock",
    "Lock",
    "Un+Lk",
    "Trunk",
    "Un+Tr",
    "Lk+Tr",
    "Un+Lk+Tr",
    "Panic!",
    "Unlock!",
    "Lock!",
    "Un+Lk!",
    "Trunk!",
    "Un+Tr!",
    "Lk+Tr!",
    "Un+Lk+Tr!",
};

void subghz_protocol_decoder_vw_2_get_string(void* context, FuriString* output) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;
    
    switch (instance->data[0]) {
        case 0xC0:
            furi_string_cat_printf(
                output,
                "%s %dbit\r\n"
                "%08X%08X%04X\r\n"
                "UID:%08lX Cnt:%06lX\r\n"
                "Type:%02X Btn:%s\r\n"
                "\r\n",
                instance->generic.protocol_name, instance->generic.data_count_bit,
                instance->data[0] << 24 | instance->data[1] << 16 | instance->data[2] << 8 | instance->data[3],
                instance->data[4] << 24 | instance->data[5] << 16 | instance->data[6] << 8 | instance->data[7],
                instance->data[8] << 8 | instance->data[9],
                instance->generic.serial, instance->generic.cnt,
                instance->data[0], subghz_protocol_vw_2_buttons[instance->generic.btn]);
            break;
        default:
            furi_string_cat_printf(
                output,
                "%s %dbit\r\n"
                "%08X%08X%04X\r\n"
                "Type:%02X\r\n"
                "Unknown type/key\r\n",
                instance->generic.protocol_name, instance->generic.data_count_bit,
                instance->data[0] << 24 | instance->data[1] << 16 | instance->data[2] << 8 | instance->data[3],
                instance->data[4] << 24 | instance->data[5] << 16 | instance->data[6] << 8 | instance->data[7],
                instance->data[8] << 8 | instance->data[9],
                instance->data[0]);
            break;
    }
}

void subghz_protocol_decoder_vw_2_get_string_brief(void* context, FuriString* output) {
    furi_assert(context);
    SubGhzProtocolDecoderVw2* instance = context;
    subghz_protocol_vw_2_decode_data(&instance->generic, instance->data);
    
    uint8_t data_hash;
    
    switch (instance->data[0]) {
        case 0xC0:
            furi_string_cat_printf(
                output,
                "%s %08lX %s",
                instance->generic.protocol_name,
                instance->generic.serial,
                subghz_protocol_vw_2_buttons[instance->generic.btn]);
            break;
        default:
            data_hash = subghz_protocol_blocks_xor_bytes(
                (const uint8_t*)&instance->data, 10);
    
            furi_string_cat_printf(
                output,
                "%s Unknown %02X",
                instance->generic.protocol_name, data_hash);
            break;
    }
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

static void subghz_protocol_vw_2_decode_data(SubGhzBlockGeneric* generic, const uint8_t* data) {
    furi_assert(generic);

    if (data[0] == 0xC0) {
        const uint8_t* encrypted = data + 1;
        uint8_t* decrypted = (uint8_t *)&generic->data;

        FURI_LOG_D(TAG, "Before decrypt: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9]);
        memcpy(decrypted, encrypted, 8);
        aut64_decrypt(key, decrypted);
        FURI_LOG_D(TAG, "After decrypt: %02X%02X%02X%02X%02X%02X%02X%02X",
            decrypted[0], decrypted[1], decrypted[2], decrypted[3], decrypted[4], decrypted[5], decrypted[6], decrypted[7]);

        if (decrypted[7] >> 4 != data[9] >> 4) {
            // Invalid packet
            return;
        }
        
        generic->serial = decrypted[0] << 24 | decrypted[1] << 16 | decrypted[2] << 8 | decrypted[3];
        generic->cnt = decrypted[6] << 16 | decrypted[5] << 8 | decrypted[4];
        generic->btn = decrypted[7] >> 4;
    }

    // Save original button for later use
    if (subghz_custom_btn_get_original() == 0) {
        subghz_custom_btn_set_original(generic->btn);
    }
    
    subghz_custom_btn_set_max(4);
}

static void subghz_protocol_vw_2_encode_data(SubGhzBlockGeneric* generic, uint8_t* data) {
    furi_assert(generic);
    
    if (data[0] == 0xC0) {
        uint8_t* decrypted = (uint8_t *)&generic->data;
        uint8_t* encrypted = data + 1;
        
        decrypted[0] = generic->serial >> 24;
        decrypted[1] = (generic->serial >> 16) & 0xFF;
        decrypted[2] = (generic->serial >> 8) & 0xFF;
        decrypted[3] = generic->serial & 0xFF;
        decrypted[4] = generic->cnt & 0xFF;
        decrypted[5] = (generic->cnt >> 8) & 0xFF;
        decrypted[6] = (generic->cnt >> 16) & 0xFF;
        decrypted[7] = generic->btn << 4;
        
        FURI_LOG_D(TAG, "Before encrypt: %02X%02X%02X%02X%02X%02X%02X%02X",
            decrypted[0], decrypted[1], decrypted[2], decrypted[3], decrypted[4], decrypted[5], decrypted[6], decrypted[7]);
        memcpy(encrypted, decrypted, 8);
        aut64_encrypt(key, encrypted);
        
        data[9] = generic->btn << 4;

        switch (generic->btn) {
            case 0x1:
            case 0x6:
                data[9] |= 0x0D;
                break;
            case 0x2:
            case 0x5:
                data[9] |= 0x0B;
                break;
            case 0x3:
            case 0x4:
                data[9] |= 0x07;
                break;
            case 0x7:
                data[9] |= 0x01;
                break;
            // TODO 0x80 Panic button + combinations
        }

        FURI_LOG_D(TAG, "After encrypt: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9]);
    }
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
        if(instance->base.callback) {
            instance->base.callback(&instance->base, instance->base.context);
        } else {
            subghz_protocol_decoder_vw_2_reset(instance);
        }
    }
}
