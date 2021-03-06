/* wspy_register.h
 *
 * Wireshark Protocol Python Binding
 *
 * Copyright (c) 2009 by Sebastien Tandel <sebastien [AT] tandel [dot] be>
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __WS_PY_REGISTER_H__
#define __WS_PY_REGISTER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HAVE_PYTHON
void register_all_py_protocols_func(void);
void register_all_py_handoffs_func(void);

WS_DLL_PUBLIC
dissector_handle_t py_create_dissector_handle(const int proto);
WS_DLL_PUBLIC
void py_dissector_args(tvbuff_t ** tvb, packet_info ** pinfo, proto_tree ** tree);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __WS_PY_REGISTER_H__ */
