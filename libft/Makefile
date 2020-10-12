# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: etieberg <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2016/11/08 20:01:36 by etieberg          #+#    #+#              #
#    Updated: 2020/10/12 13:18:33 by etieberg         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

SRC_PATH = .

SRC_NAME = ft_memset.c				\
	  ft_malloc_check.c			\
	  ft_bzero.c				\
	  ft_memcpy.c				\
	  ft_memccpy.c				\
	  ft_memmove.c				\
	  ft_memchr.c				\
	  ft_memcmp.c				\
	  ft_strlen.c				\
	  ft_strdup.c				\
	  ft_strcpy.c				\
	  ft_strncpy.c				\
	  ft_strcat.c				\
	  ft_strncat.c				\
	  ft_strlcat.c				\
	  ft_strchr.c				\
	  ft_strrchr.c				\
	  ft_strichr.c				\
	  ft_strstr.c				\
	  ft_strchrr.c				\
	  ft_strnstr.c				\
	  ft_strcmp.c				\
	  ft_strncmp.c				\
	  ft_arraylen.c				\
	  ft_arraydup.c				\
	  ft_atoi.c					\
	  ft_isalpha.c				\
	  ft_isdigit.c				\
	  ft_isalnum.c				\
	  ft_isascii.c				\
	  ft_isprint.c				\
	  ft_toupper.c				\
	  ft_tolower.c				\
	  ft_memalloc.c				\
	  ft_memdel.c				\
	  ft_strnew.c				\
	  ft_strdel.c				\
	  ft_strclr.c				\
	  ft_striter.c				\
	  ft_striteri.c				\
	  ft_strmap.c				\
	  ft_strmapi.c				\
	  ft_strequ.c				\
	  ft_strnequ.c				\
	  ft_strsub.c				\
	  ft_strjoin.c				\
	  ft_strjoinfree.c			\
	  ft_strtrim.c				\
	  ft_putchar.c				\
	  ft_putstr.c				\
	  ft_putendl.c				\
	  ft_putnbr.c				\
	  ft_putchar_fd.c			\
	  ft_putstr_fd.c			\
	  ft_putendl_fd.c			\
	  ft_putnbr_fd.c			\
	  ft_itoa.c					\
	  ft_itoabase.c				\
	  ft_strsplit.c				\
	  ft_lstnew.c				\
	  ft_lstdelone.c			\
	  ft_lstdel.c				\
	  ft_lstadd.c				\
	  ft_lstiter.c				\
	  ft_lstmap.c				\
	  ft_sqrt.c					\
	  ft_foreach.c				\
	  ft_range.c				\
	  ft_recursive_factorial.c	\
	  ft_iswhitespace.c			\
	  ft_wstrlen.c				\
	  ft_wcharlen.c				\
	  ft_wstrcpy.c				\
	  ft_charcmp.c				\
	  ft_charjoin.c				\
	  ft_intlen.c				\
	  ft_realloc.c				\
	  ft_free.c					\
	  ft_stradd.c				\
	  get_next_line.c			\
	  ft_get_input.c			\
	  ft_numlen.c				\
	  ft_putstrn.c				\
	  ft_unicode_putchar.c	\
	  ft_printf/ft_printf.c		\
	  ft_printf/ft_putbase.c \
	ft_printf/num_flags.c \
	ft_printf/num_flags_cont.c \
	ft_printf/num_printers.c \
	ft_printf/print_chars.c \
	ft_printf/print_numbers.c \
	ft_printf/unicode.c \
	ft_printf/fd.c

CPPFLAGS = -I Includes

FLAGS = -Wall -Wextra -Werror -O3

OBJ_NAME = $(SRC_NAME:.c=.o)

OBJ_PATH = obj

DEPS = includes/libft.h \
		includes/ft_printf.h \
		includes/get_next_line.h \

NAME = libft.a

SRC = $(addprefix $(SRC_PATH)/,$(SRC_NAME))

OBJ = $(addprefix $(OBJ_PATH)/,$(OBJ_NAME))

all: $(NAME)

$(NAME): $(OBJ)
	@ar rc $@ $^
	@echo "###\nlibftprintf.a compiled"

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c $(DEPS)
	@mkdir -p $(OBJ_PATH)
	@mkdir -p $(dir $(OBJ))
	@gcc $(FLAGS) -o $@ -c $< $(CPPFLAGS)
	@echo "#" | tr -d '\n'


clean:
	rm -rf $(OBJ_PATH)

fclean: clean
	rm -f $(NAME)

re:
	$(MAKE) fclean
	$(MAKE) all
