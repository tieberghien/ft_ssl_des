/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   shift_des.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/20 13:58:24 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/20 14:28:40 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint32_t	bitnum(uint32_t x[], int m, int n)
{
	 return (((x[(m) / 8] >> (7 - (m % 8))) & 0x01) << (n));
}

uint32_t	bitnumintr(uint32_t x, int m, int n)
{
	return ((((x) >> (31 - (m))) & 0x00000001) << (n));
}

uint32_t	bitnumintl(uint32_t x, int m, int n)
{
	return ((((x) << (m)) & 0x80000000) >> (n));
}
