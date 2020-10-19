/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_opts.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etieberg <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/11 12:08:46 by etieberg          #+#    #+#             */
/*   Updated: 2020/10/12 11:37:29 by etieberg         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

int		parse_opts(char *flag, t_options *opts, int i)
{
	if (!(ft_strcmp(flag, "-a")))
		opts->base = 1;
	else if (!(ft_strcmp(flag, "-d")))
		opts->dec = 1;
	else if (!(ft_strcmp(flag, "-e")))
		opts->enc = 1;
	else if (!(ft_strcmp(flag, "-i")))
		opts->input = i;
	else if (!(ft_strcmp(flag, "-k")))
		opts->key = i;
	else if (!(ft_strcmp(flag, "-o")))
		opts->output = i;
	else if (!(ft_strcmp(flag, "-p")))
		opts->pass = i;
	else if (!(ft_strcmp(flag, "-s")))
		opts->salt = i;
	else if (!(ft_strcmp(flag, "-v")))
		opts->iv = i;
	return (1);
}

int		init_pbkdf(t_pbkdf *pbkdf, t_options *opts, char **av)
{
	if (opts->pass)
	{
		if (av[opts->pass + 1])
			pbkdf->pass = (const uint8_t *)ft_strdup(av[opts->pass + 1]);
		else
		{
			ft_putendl("missing source argument for -p");
			return (0);
		}
	}
	if (opts->input)
	{
		if (av[opts->input + 1])
			pbkdf->input = (const uint8_t *)ft_strdup(av[opts->input + 1]);
		else
			ft_putendl("missing file argument for -i");
	}
	if (opts->output)
	{
		if (av[opts->input + 1])
			pbkdf->output = (const uint8_t *)ft_strdup(av[opts->output + 1]);
		else
			ft_putendl("missing file argument for -o");
	}
	if (opts->salt)
	{
		if (av[opts->salt + 1])
			pbkdf->salt = (const uint8_t *)ft_strdup(av[opts->salt + 1]);
		else
			ft_putendl("missing salt argument for -s");
	}
	return (1);
}

int		invalid_opts(char *cmd, t_options *opts)
{
	if (ft_strncmp("base64", cmd, 6) == 0 && (opts->key || opts->pass
				|| opts->salt || opts->base || opts->iv))
	{
		ft_putstr("base64: invalid option --\n");
		return (0);
	}
	return (1);
}
