/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rotation.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 19:12:36 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/15 13:31:59 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint32_t	right_rotation(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}

uint32_t	left_rotation(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

uint64_t	right_rotation_64(uint64_t x, int n)
{
	return (x >> n) | (x << (64 - n));
}

uint64_t	left_rotation_64(uint64_t x, int n)
{
	return (x << n) | (x >> (64 - n));
}
