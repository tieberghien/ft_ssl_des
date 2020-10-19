/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/12 14:22:32 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 16:02:33 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static int mod_table[] = {0, 2, 1};

static const uint8_t g_charset[]={ "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
									"abcdefghijklmnopqrstuvwxyz"
									"0123456789+/"};

static char *decoding_table = NULL;

uint8_t revchar(char ch)
{
	if (ch >= 'A' && ch <= 'Z')
		ch -= 'A';
	else if (ch >= 'a' && ch <='z')
		ch = ch - 'a' + 26;
	else if (ch >= '0' && ch <='9')
		ch = ch - '0' + 52;
	else if (ch == '+')
		ch = 62;
	else if (ch == '/')
		ch = 63;
	return (ch);
}

void	base64_encode(char *data, t_options *opts)
{
	(void)opts;
	size_t input_length;
	size_t output_length;

	input_length = ft_strlen(data);
	output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(output_length);
    if (encoded_data == NULL) return;

    for (int i = 0, j = 0; i < (int)input_length;) {

        uint32_t octet_a = i < (int)input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < (int)input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < (int)input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = g_charset[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = g_charset[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = g_charset[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = g_charset[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
    puts(encoded_data);
}

void	build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[g_charset[i]] = i;
}

void    base64_decode(char *data, t_options *opts)
{
	(void)opts;
	size_t input_length;
	size_t output_length; //has to be parameter for file size

	if (decoding_table == NULL) build_decoding_table();
	input_length = ft_strlen(data);
    if (input_length % 4 != 0) return;

    output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (output_length)--;
    if (data[input_length - 2] == '=') (output_length)--;

    unsigned char *decoded_data = malloc(output_length);
    if (decoded_data == NULL) return;

    for (int i = 0, j = 0; i < (int)input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[i++];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[i++];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[i++];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[i++];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < (int)output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < (int)output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < (int)output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
	puts((char*)decoded_data);
}

void	base64(char *message, t_options *opts, char **av)
{
	(void)av;
	if (opts->dec)
		base64_decode(message, opts);
	else
		base64_encode(message, opts);	
}
