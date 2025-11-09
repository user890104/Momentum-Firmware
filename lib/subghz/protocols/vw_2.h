#pragma once

#include <stdint.h>

#define AUT64_NUM_ROUNDS 12
#define AUT64_BLOCK_SIZE 8
#define AUT64_KEY_SIZE 8
#define AUT64_PBOX_SIZE 8
#define AUT64_SBOX_SIZE 16

struct aut64_key {
    uint8_t key[AUT64_KEY_SIZE];
    uint8_t pbox[AUT64_PBOX_SIZE];
    uint8_t sbox[AUT64_SBOX_SIZE];
};

void aut64_encrypt(const struct aut64_key key, uint8_t message[]);
void aut64_decrypt(const struct aut64_key key, uint8_t message[]);

#include "base.h"

#ifndef REVERSE_BYTES_U64
#define REVERSE_BYTES_U64(x) (REVERSE_BYTES_U32((x) >> 32) | REVERSE_BYTES_U32((x) & 0xFFFFFFFF) << 32)
#endif

#define SUBGHZ_PROTOCOL_VW_2_NAME "VW-2"

typedef struct SubGhzProtocolDecoderVw2 SubGhzProtocolDecoderVw2;
typedef struct SubGhzProtocolEncoderVw2 SubGhzProtocolEncoderVw2;

extern const SubGhzProtocolDecoder subghz_protocol_vw_2_decoder;
extern const SubGhzProtocolEncoder subghz_protocol_vw_2_encoder;
extern const SubGhzProtocol subghz_protocol_vw_2;

/**
 * Allocate SubGhzProtocolEncoderVw2.
 * @param environment Pointer to a SubGhzEnvironment instance
 * @return SubGhzProtocolEncoderVw2* pointer to a SubGhzProtocolEncoderVw2 instance
 */
void* subghz_protocol_encoder_vw_2_alloc(SubGhzEnvironment* environment);

/**
 * Free SubGhzProtocolEncoderVw2.
 * @param context Pointer to a SubGhzProtocolEncoderVw2 instance
 */
void subghz_protocol_encoder_vw_2_free(void* context);

/**
 * Deserialize and generating an upload to send.
 * @param context Pointer to a SubGhzProtocolEncoderVw2 instance
 * @param flipper_format Pointer to a FlipperFormat instance
 * @return status
 */
SubGhzProtocolStatus
    subghz_protocol_encoder_vw_2_deserialize(void* context, FlipperFormat* flipper_format);

/**
 * Forced transmission stop.
 * @param context Pointer to a SubGhzProtocolEncoderVw2 instance
 */
void subghz_protocol_encoder_vw_2_stop(void* context);

/**
 * Getting the level and duration of the upload to be loaded into DMA.
 * @param context Pointer to a SubGhzProtocolEncoderVw2 instance
 * @return LevelDuration 
 */
LevelDuration subghz_protocol_encoder_vw_2_yield(void* context);

/**
 * Allocate SubGhzProtocolDecoderVw2.
 * @param environment Pointer to a SubGhzEnvironment instance
 * @return SubGhzProtocolDecoderVw2* pointer to a SubGhzProtocolDecoderVw2 instance
 */
void* subghz_protocol_decoder_vw_2_alloc(SubGhzEnvironment* environment);

/**
 * Free SubGhzProtocolDecoderVw2.
 * @param context Pointer to a SubGhzProtocolDecoderVw2 instance
 */
void subghz_protocol_decoder_vw_2_free(void* context);

/**
 * Reset decoder SubGhzProtocolDecoderVw2.
 * @param context Pointer to a SubGhzProtocolDecoderVw2 instance
 */
void subghz_protocol_decoder_vw_2_reset(void* context);

/**
 * Parse a raw sequence of levels and durations received from the air.
 * @param context Pointer to a SubGhzProtocolDecoderVw2 instance
 * @param level Signal level true-high false-low
 * @param duration Duration of this level in, us
 */
void subghz_protocol_decoder_vw_2_feed(void* context, bool level, uint32_t duration);

/**
 * Getting the hash sum of the last randomly received parcel.
 * @param context Pointer to a SubGhzProtocolDecoderVw2 instance
 * @return hash Hash sum
 */
uint32_t subghz_protocol_decoder_vw_2_get_hash_data(void* context);

/**
 * Serialize data SubGhzProtocolDecoderVw2.
 * @param context Pointer to a SubGhzProtocolDecoderVw2 instance
 * @param flipper_format Pointer to a FlipperFormat instance
 * @param preset The modulation on which the signal was received, SubGhzRadioPreset
 * @return status
 */
SubGhzProtocolStatus subghz_protocol_decoder_vw_2_serialize(
    void* context,
    FlipperFormat* flipper_format,
    SubGhzRadioPreset* preset);

/**
 * Deserialize data SubGhzProtocolDecoderVw2.
 * @param context Pointer to a SubGhzProtocolDecoderVw2 instance
 * @param flipper_format Pointer to a FlipperFormat instance
 * @return status
 */
SubGhzProtocolStatus
    subghz_protocol_decoder_vw_2_deserialize(void* context, FlipperFormat* flipper_format);

/**
 * Getting a textual representation of the received data.
 * @param context Pointer to a SubGhzProtocolDecoderVw2 instance
 * @param output Resulting text
 */
void subghz_protocol_decoder_vw_2_get_string(void* context, FuriString* output);

/**
 * Getting a one-line textual representation of the received data.
 * @param context Pointer to a SubGhzProtocolDecoderVw2 instance
 * @param output Resulting text
 */
void subghz_protocol_decoder_vw_2_get_string_brief(void* context, FuriString* output);
