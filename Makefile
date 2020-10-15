# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: etieberg <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2018/11/19 12:25:25 by etieberg          #+#    #+#              #
#    Updated: 2020/10/15 14:57:48 by etieberg         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME			=	ft_ssl

SRC			=	main.c		\
				parse_opts.c	\
				stdin.c		\
				selection.c \
				md5.c		\
				md5_breakdown.c \
				sha224.c	\
				sha256.c	\
				sha256_breakdown.c	\
				sha1.c			\
				rotation.c	\
				display_hash.c	\
				handle_error.c	\
				base64.c

OBJ_NAME		=	$(SRC:.c=.o)

SRC_PATH		=	src/
OBJ_PATH		=	obj/

OBJ			=	$(addprefix $(OBJ_PATH),$(OBJ_NAME))

CC			=	gcc
CFLAGS			=	-Wall -Werror -Wextra #-fsanitize=address #-03 -g
LDFLAGS			=	-Llibft -lft

INC_DIR			=	includes
INCS			=	-I $(INC_DIR) -I libft/includes/.

all:			library $(NAME)

$(NAME):		$(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_PATH)%.o:	$(SRC_PATH)%.c
	mkdir -p $(OBJ_PATH)
	$(CC) $(CFLAGS) $(INCS) -o $@ -c $<

library :
	make -C libft

clean:
	rm -fv $(OBJ)
	rm -rfv $(OBJ_PATH)
	make clean -C libft/

fclean: clean
	rm -fv $(NAME)
	make fclean -C libft/

re: fclean all

.PHONY: all, clean, fclean, re
