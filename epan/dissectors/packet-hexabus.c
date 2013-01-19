/* packet-hexabus.c
 * Routines for Hexabus dissection
 * Copyright 2012, Stephan Platz <wireshark@paalsteek.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#if 0
/* Include only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <epan/crc16-tvb.h>

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
//#include "packet-hexabus.h"

/* We use the same CRC algorithm as IEEE802.15.4. See epan/dissectors/packet-ieee802154.c for details
	 */
#define IEEE802154_CRC_SEED     0x0000
#define IEEE802154_CRC_XOROUT   0xFFFF
#define ieee802154_crc_tvb(tvb, offset)   (crc16_ccitt_tvb_seed(tvb, offset, IEEE802154_CRC_SEED) ^ IEEE802154_CRC_XOROUT)

/* Forward declaration we need below (if using proto_reg_handoff...
   as a prefs callback)       */
void proto_reg_handoff_hexabus(void);

/* Initialize the protocol and registered fields */
static int proto_hexabus = -1;
static int hf_hexabus_type = -1;
static int hf_hexabus_flags = -1;
static int hf_hexabus_eid = -1;
static int hf_hexabus_dtype = -1;
static int hf_hexabus_bool_value = -1;
static int hf_hexabus_uint8_value = -1;
static int hf_hexabus_uint32_value = -1;
static int hf_hexabus_datetime_value = -1;
static int hf_hexabus_datetime_value_hour = -1;
static int hf_hexabus_datetime_value_minute = -1;
static int hf_hexabus_datetime_value_second = -1;
static int hf_hexabus_datetime_value_day = -1;
static int hf_hexabus_datetime_value_month = -1;
static int hf_hexabus_datetime_value_year = -1;
static int hf_hexabus_datetime_value_weekday = -1;
static int hf_hexabus_float_value = -1;
static int hf_hexabus_128string_value = -1;
static int hf_hexabus_timestamp_value = -1;
static int hf_hexabus_endpoint = -1;
static int hf_hexabus_error = -1;
static int hf_hexabus_crc = -1;
static int hf_hexabus_crc_good = -1;
static int hf_hexabus_crc_bad = -1;

static expert_field ei_hexabus_bad_checksum = EI_INIT;

static ei_register_info ei[] = {
	{ &ei_hexabus_bad_checksum, { "hexabus.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
};

/* Global sample preference ("controls" display of numbers) */
static gboolean gPREF_HEX = FALSE;
/* Global sample port pref */
static guint gPORT_PREF = 61616;

/* Initialize the subtree pointers */
static gint ett_hexabus = -1;
static gint ett_hexabus_datetime = -1;
static gint ett_hexabus_flags = -1;
static gint ett_hexabus_crc = -1;

struct datetime {
    gint8   hour;
    gint8   minute;
    gint8   second;
    gint8   day;
    gint8   month;
    gint16  year;
    gint8   weekday;  // numbers from 0 to 6, sunday as the first day of the week.
} __attribute__ ((packed));

static const value_string hf_hexabus_type_names[] = {
	{ 0x0, "Error Packet" },
	{ 0x1, "Info Packet" },
	{ 0x2, "Query Packet" },
	{ 0x4, "Write Packet" },
	{ 0x9, "Endpoint Info Packet" },
	{ 0xA, "Endpoint Query Packet" },
	{ 0, NULL }
};

static const value_string hf_hexabus_eid_names[] = {
	{ 0, "Hexabus device descriptor" },
	{ 1, "HexabusPlug relay" },
	{ 2, "HexabusPlug+ power meter" },
	{ 3, "Temperature sensor" },
	{ 4, "internal Button (on board / plug)" },
	{ 5, "Humidity sensor" },
	{ 6, "Barometric pressure sensor" },
	{ 7, "HexabusPlug+ energy meter total" },
	{ 8, "HexabusPlug+ energy meter user resettable" },
	{ 9, "Statemachine control" },
	{ 10, "Statemachine upload receiver" },
	{ 11, "Statemachine upload ack/nack" },
	{ 12, "Statemachine emergency reset ID" },
	{ 20, "LED / Hexagl0w Color" },
	{ 21, "Power meter [Flukso]" },
	{ 22, "Analogread" },
	{ 23, "Window shutter" },
	{ 24, "Hexapush pressed buttons" },
	{ 25, "Hexapush clicked buttons" },
	{ 26, "Presence detector" },
	{ 27, "Hexonoff set" },
	{ 28, "Hexonoff toggle" },
	{ 29, "Lightsensor" },
	{ 30, "IR receiver" },
	{ 31, "Node liveness" },
	{ 33, "Generic dial gauge #0" },
	{ 34, "Generic dial gauge #1" },
	{ 35, "Generic dial gauge #2" },
	{ 36, "Generic dial gauge #3" },
	{ 37, "Generic dial gauge #4" },
	{ 38, "Generic dial gauge #5" },
	{ 39, "Generic dial gauge #6" },
	{ 40, "Generic dial gauge #7" },
	{ 41, "PV power production measurement" },
	{ 42, "Power balance (Production - Consumption)" },
	{ 43, "Battery power balance (in - out)" },
	{ 44, "Temperatur sensor for heater inflow" },
	{ 45, "Temperatur sensor for heater outflow" },
	{ 46, "Hexasense button state" },
	{ 47, "Flukso Phase 1" },
	{ 48, "Flukso Phase 2" },
	{ 49, "Flukso Phase 3" },
	{ 50, "Flukso S0 1" },
	{ 51, "Flukso S0 2" },
	{ 0, NULL }
};

static const value_string hf_hexabus_dtype_names[] = {
	{ 0x00, "Undefined" },
	{ 0x01, "Boolean" },
	{ 0x02, "Unsigned 8 bit integer" },
	{ 0x03, "Unsigned 32 bit integer" },
	{ 0x04, "Date and time" },
	{ 0x05, "32 bit floating point" },
	{ 0x06, "128 char fixed length string" },
	{ 0x07, "timestamp" },
	{ 0, NULL }
};

static const value_string hf_hexabus_weekday_names[] = {
	{ 0, "Sunday" },
	{ 1, "Monday" },
	{ 2, "Tuesday" },
	{ 3, "Wednesday" },
	{ 4, "Thursday" },
	{ 5, "Friday" },
	{ 6, "Saturday" },
	{ 0, NULL }
};

static const value_string hf_hexabus_error_names[] = {
	{ 0x01, "Unknown EID" },
	{ 0x02, "Write Read-Only" },
	{ 0x03, "CRC Failed" },
	{ 0x04, "Data type mismatch" },
	{ 0, NULL }
};

/* Code to actually dissect the packets */
static int
dissect_hexabus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *hexabus_tree;
	proto_tree *hexabus_datetime_tree;
	//proto_tree *hexabus_flags_tree;
	proto_tree *hexabus_crc_tree;
	unsigned int version = 0;
	guint16 crc, checksum;

/*  First, if at all possible, do some heuristics to check if the packet cannot
 *  possibly belong to your protocol.  This is especially important for
 *  protocols directly on top of TCP or UDP where port collisions are
 *  common place (e.g., even though your protocol uses a well known port,
 *  someone else may set up, for example, a web server on that port which,
 *  if someone analyzed that web server's traffic in Wireshark, would result
 *  in Wireshark handing an HTTP packet to your dissector).  For example:
 */
	/* Check that there's enough data */
	if (tvb_length(tvb) < 9)
		return 0;

	/* Get some values from the packet header, probably using tvb_get_*() */
	switch ( tvb_get_bits32(tvb, 0, 32, 0) )
	{
		case 0x48583042:
			version = 1;
			break;
		case 0x48583043:
			version = 2;
			break;
	}

	if ( version == 0 ) {
		/*  This packet does not appear to belong to Hexabus.
		 *  Return 0 to give another dissector a chance to dissect it.
		 */
		return 0;
	}

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "hexabus");

	/* This field shows up as the "Info" column in the display; you should use
		 it, if possible, to summarize what's in the packet, so that a user looking
		 at the list of packets can tell what type of packet it is. See section 1.5
		 for more information.

		 If you are setting the column to a constant string, use "col_set_str()",
		 as it's more efficient than the other "col_set_XXX()" calls.

		 If you're setting it to a string you've constructed, or will be
		 appending to the column later, use "col_add_str()".

		 "col_add_fstr()" can be used instead of "col_add_str()"; it takes
		 "printf()"-like arguments. Don't use "col_add_fstr()" with a format
		 string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
		 more efficient than "col_add_fstr()".

		 If you will be fetching any data from the packet before filling in
		 the Info column, clear that column first, in case the calls to fetch
		 data from the packet throw an exception because they're fetching data
		 past the end of the packet, so that the Info column doesn't have data
		 left over from the previous dissector; do

		 col_clear(pinfo->cinfo, COL_INFO);

	 */

	/* A protocol dissector may be called in 2 different ways - with, or
		 without a non-null "tree" argument.

		 If the proto_tree argument is null, Wireshark does not need to use
		 the protocol tree information from your dissector, and therefore is
		 passing the dissector a null "tree" argument so that it doesn't
		 need to do work necessary to build the protocol tree.

		 In the interest of speed, if "tree" is NULL, avoid building a
		 protocol tree and adding stuff to it, or even looking at any packet
		 data needed only if you're building the protocol tree, if possible.

		 Note, however, that you must fill in column information, create
		 conversations, reassemble packets, build any other persistent state
		 needed for dissection, and call subdissectors regardless of whether
		 "tree" is NULL or not. This might be inconvenient to do without
		 doing most of the dissection work; the routines for adding items to
		 the protocol tree can be passed a null protocol tree pointer, in
		 which case they'll return a null item pointer, and
		 "proto_item_add_subtree()" returns a null tree pointer if passed a
		 null item pointer, so, if you're careful not to dereference any null
		 tree or item pointers, you can accomplish this by doing all the
		 dissection work. This might not be as efficient as skipping that
		 work if you're not building a protocol tree, but if the code would
		 have a lot of tests whether "tree" is null if you skipped that work,
		 you might still be better off just doing all that work regardless of
		 whether "tree" is null or not.

		 Note also that there is no guarantee, the first time the dissector is
		 called, whether "tree" will be null or not; your dissector must work
		 correctly, building or updating whatever state information is
		 necessary, in either case. */

	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_hexabus, tvb, 0, -1, ENC_NA);

	hexabus_tree = proto_item_add_subtree(ti, ett_hexabus);

	if ( version == 1 )
	{
		if (tree) {

			guint8 type;
			guint8 dtype;
			guint8 hour, minute, second, day, month, weekday;
			guint16 year;
			guint32 timestamp;

			/* NOTE: The offset and length values in the call to
				 "proto_tree_add_item()" define what data bytes to highlight in the hex
				 display window when the line in the protocol tree display
				 corresponding to that item is selected.

				 Supplying a length of -1 is the way to highlight all data from the
				 offset to the end of the packet. */

			/* add an item to the subtree, see section 1.6 for more information */
			proto_tree_add_item(hexabus_tree,
					hf_hexabus_type, tvb, 4, 1, ENC_BIG_ENDIAN);

			type = tvb_get_guint8(tvb, 4);
			ti = proto_tree_add_item(hexabus_tree,
					hf_hexabus_flags, tvb, 5, 1, ENC_BIG_ENDIAN);
			//hexabus_flags_tree = proto_item_add_subtree(ti, ett_hexabus_flags);
			//TODO: build subtree for flags
			switch (type)
			{
				case 0:
					col_set_str(pinfo->cinfo, COL_INFO, "Error Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_error, tvb, 6, 1, ENC_BIG_ENDIAN);
					break;
				case 1:
					col_set_str(pinfo->cinfo, COL_INFO, "Info Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_dtype, tvb, 7, 1, ENC_BIG_ENDIAN);
					dtype = tvb_get_guint8(tvb, 7);
					switch (dtype)
					{
						case 0x00:
							break;
						case 0x01:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_bool_value, tvb, 8, 1, ENC_BIG_ENDIAN);
							break;
						case 0x02:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_uint8_value, tvb, 8, 1, ENC_BIG_ENDIAN);
							break;
						case 0x03:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_uint32_value, tvb, 8, 4, ENC_BIG_ENDIAN);
							break;
						case 0x04:
							hour = tvb_get_guint8(tvb, 8);
							minute = tvb_get_guint8(tvb, 9);
							second = tvb_get_guint8(tvb, 10);
							day = tvb_get_guint8(tvb, 11);
							month = tvb_get_guint8(tvb, 12);
							year = tvb_get_ntohs(tvb, 13);
							weekday = tvb_get_guint8(tvb, 15);
							ti = proto_tree_add_uint64_format_value(hexabus_tree, hf_hexabus_datetime_value, tvb, 8, 8, tvb_get_ntoh64(tvb, 8), "%d:%d:%d %d.%d.%d Weekday: %d", hour, minute, second, day, month, year, weekday);
							hexabus_datetime_tree = proto_item_add_subtree(ti, ett_hexabus_datetime);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_hour, tvb, 8, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_minute, tvb, 9, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_second, tvb, 10, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_day, tvb, 11, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_month, tvb, 12, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_year, tvb, 13, 2, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_weekday, tvb, 15, 1, ENC_BIG_ENDIAN);
							break;
						case 0x05:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_float_value, tvb, 8, 4, ENC_BIG_ENDIAN);
							break;
						case 0x06:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_128string_value, tvb, 8, 128, ENC_BIG_ENDIAN);
							break;
						case 0x07:
							timestamp = tvb_get_ntohl(tvb, 8);
							proto_tree_add_uint_format_value(hexabus_tree,
									hf_hexabus_timestamp_value, tvb, 8, 4, timestamp, "%u seconds", timestamp);
							break;
					}
					break;
				case 2:
					col_set_str(pinfo->cinfo, COL_INFO, "Query Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 1, ENC_BIG_ENDIAN);
					break;
				case 4:
					col_set_str(pinfo->cinfo, COL_INFO, "Write Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_dtype, tvb, 7, 1, ENC_BIG_ENDIAN);
					dtype = tvb_get_guint8(tvb, 7);
					switch (dtype)
					{
						case 0x00:
							break;
						case 0x01:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_bool_value, tvb, 8, 1, ENC_BIG_ENDIAN);
							break;
						case 0x02:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_uint8_value, tvb, 8, 1, ENC_BIG_ENDIAN);
							break;
						case 0x03:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_uint32_value, tvb, 8, 4, ENC_BIG_ENDIAN);
							break;
						case 0x04:
							hour = tvb_get_guint8(tvb, 8);
							minute = tvb_get_guint8(tvb, 9);
							second = tvb_get_guint8(tvb, 10);
							day = tvb_get_guint8(tvb, 11);
							month = tvb_get_guint8(tvb, 12);
							year = tvb_get_ntohs(tvb, 13);
							weekday = tvb_get_guint8(tvb, 15);
							ti = proto_tree_add_uint64_format_value(hexabus_tree, hf_hexabus_datetime_value, tvb, 8, 8, tvb_get_ntoh64(tvb, 8), "%d:%d:%d %d.%d.%d Weekday: %d", hour, minute, second, day, month, year, weekday);
							hexabus_datetime_tree = proto_item_add_subtree(ti, ett_hexabus_datetime);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_hour, tvb, 8, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_minute, tvb, 9, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_second, tvb, 10, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_day, tvb, 11, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_month, tvb, 12, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_year, tvb, 13, 2, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_weekday, tvb, 15, 1, ENC_BIG_ENDIAN);
							break;
						case 0x05:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_float_value, tvb, 8, 4, ENC_BIG_ENDIAN);
							break;
						case 0x06:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_128string_value, tvb, 8, 128, ENC_BIG_ENDIAN);
							break;
						case 0x07:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_timestamp_value, tvb, 8, 4, ENC_BIG_ENDIAN);
							break;
					}
					break;
				case 9:
					col_set_str(pinfo->cinfo, COL_INFO, "Endpoint Info Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_dtype, tvb, 7, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_endpoint, tvb, 8, 128, ENC_BIG_ENDIAN);
					break;
				case 10:
					col_set_str(pinfo->cinfo, COL_INFO, "Endpoint Query Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 1, ENC_BIG_ENDIAN);
					break;
			}

		}
	} else if ( version == 2 ) {
		if (tree) {

			guint8 type;
			guint8 dtype;
			guint8 hour, minute, second, day, month, weekday;
			guint16 year;
			guint32 timestamp;

			/* NOTE: The offset and length values in the call to
				 "proto_tree_add_item()" define what data bytes to highlight in the hex
				 display window when the line in the protocol tree display
				 corresponding to that item is selected.

				 Supplying a length of -1 is the way to highlight all data from the
				 offset to the end of the packet. */

			/* add an item to the subtree, see section 1.6 for more information */
			proto_tree_add_item(hexabus_tree,
					hf_hexabus_type, tvb, 4, 1, ENC_BIG_ENDIAN);

			type = tvb_get_guint8(tvb, 4);
			ti = proto_tree_add_item(hexabus_tree,
					hf_hexabus_flags, tvb, 5, 1, ENC_BIG_ENDIAN);
			//hexabus_flags_tree = proto_item_add_subtree(ti, ett_hexabus_flags);
			//TODO: build subtree for flags
			switch (type)
			{
				case 0:
					col_set_str(pinfo->cinfo, COL_INFO, "Error Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_error, tvb, 6, 1, ENC_BIG_ENDIAN);
					break;
				case 1:
					col_set_str(pinfo->cinfo, COL_INFO, "Info Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_dtype, tvb, 10, 1, ENC_BIG_ENDIAN);
					dtype = tvb_get_guint8(tvb, 10);
					switch (dtype)
					{
						case 0x00:
							break;
						case 0x01:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_bool_value, tvb, 11, 1, ENC_BIG_ENDIAN);
							break;
						case 0x02:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_uint8_value, tvb, 11, 1, ENC_BIG_ENDIAN);
							break;
						case 0x03:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_uint32_value, tvb, 11, 4, ENC_BIG_ENDIAN);
							break;
						case 0x04:
							hour = tvb_get_guint8(tvb, 11);
							minute = tvb_get_guint8(tvb, 12);
							second = tvb_get_guint8(tvb, 13);
							day = tvb_get_guint8(tvb, 14);
							month = tvb_get_guint8(tvb, 15);
							year = tvb_get_ntohs(tvb, 16);
							weekday = tvb_get_guint8(tvb, 17);
							ti = proto_tree_add_uint64_format_value(hexabus_tree, hf_hexabus_datetime_value, tvb, 11, 8, tvb_get_ntoh64(tvb, 11), "%d:%d:%d %d.%d.%d Weekday: %d", hour, minute, second, day, month, year, weekday);
							hexabus_datetime_tree = proto_item_add_subtree(ti, ett_hexabus_datetime);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_hour, tvb, 11, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_minute, tvb, 12, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_second, tvb, 13, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_day, tvb, 14, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_month, tvb, 15, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_year, tvb, 16, 2, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_weekday, tvb, 18, 1, ENC_BIG_ENDIAN);
							break;
						case 0x05:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_float_value, tvb, 11, 4, ENC_BIG_ENDIAN);
							break;
						case 0x06:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_128string_value, tvb, 11, 128, ENC_BIG_ENDIAN);
							break;
						case 0x07:
							timestamp = tvb_get_ntohl(tvb, 11);
							proto_tree_add_uint_format_value(hexabus_tree,
									hf_hexabus_timestamp_value, tvb, 11, 4, timestamp, "%u seconds", timestamp);
							break;
					}
					break;
				case 2:
					col_set_str(pinfo->cinfo, COL_INFO, "Query Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 4, ENC_BIG_ENDIAN);
					break;
				case 4:
					col_set_str(pinfo->cinfo, COL_INFO, "Write Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_dtype, tvb, 10, 1, ENC_BIG_ENDIAN);
					dtype = tvb_get_guint8(tvb, 10);
					switch (dtype)
					{
						case 0x00:
							break;
						case 0x01:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_bool_value, tvb, 11, 1, ENC_BIG_ENDIAN);
							break;
						case 0x02:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_uint8_value, tvb, 11, 1, ENC_BIG_ENDIAN);
							break;
						case 0x03:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_uint32_value, tvb, 11, 4, ENC_BIG_ENDIAN);
							break;
						case 0x04:
							hour = tvb_get_guint8(tvb, 11);
							minute = tvb_get_guint8(tvb, 12);
							second = tvb_get_guint8(tvb, 13);
							day = tvb_get_guint8(tvb, 14);
							month = tvb_get_guint8(tvb, 15);
							year = tvb_get_ntohs(tvb, 16);
							weekday = tvb_get_guint8(tvb, 17);
							ti = proto_tree_add_uint64_format_value(hexabus_tree, hf_hexabus_datetime_value, tvb, 11, 8, tvb_get_ntoh64(tvb, 8), "%d:%d:%d %d.%d.%d Weekday: %d", hour, minute, second, day, month, year, weekday);
							hexabus_datetime_tree = proto_item_add_subtree(ti, ett_hexabus_datetime);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_hour, tvb, 11, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_minute, tvb, 12, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_second, tvb, 13, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_day, tvb, 14, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_month, tvb, 15, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_year, tvb, 16, 2, ENC_BIG_ENDIAN);
							proto_tree_add_item(hexabus_datetime_tree,
									hf_hexabus_datetime_value_weekday, tvb, 18, 1, ENC_BIG_ENDIAN);
							break;
						case 0x05:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_float_value, tvb, 11, 4, ENC_BIG_ENDIAN);
							break;
						case 0x06:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_128string_value, tvb, 11, 128, ENC_BIG_ENDIAN);
							break;
						case 0x07:
							proto_tree_add_item(hexabus_tree,
									hf_hexabus_timestamp_value, tvb, 11, 4, ENC_BIG_ENDIAN);
							break;
					}
					break;
				case 9:
					col_set_str(pinfo->cinfo, COL_INFO, "Endpoint Info Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_dtype, tvb, 10, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_endpoint, tvb, 11, 128, ENC_BIG_ENDIAN);
					break;
				case 10:
					col_set_str(pinfo->cinfo, COL_INFO, "Endpoint Query Packet");
					proto_tree_add_item(hexabus_tree,
							hf_hexabus_eid, tvb, 6, 4, ENC_BIG_ENDIAN);
					break;
			}
		}
	}
	crc = ieee802154_crc_tvb(tvb, tvb_length(tvb)-2);
	checksum = tvb_get_ntohs(tvb, tvb_length(tvb)-2);
	if ( crc == checksum )
	{
		ti = proto_tree_add_uint_format(hexabus_tree, hf_hexabus_crc, tvb, tvb_length(tvb)-2, 2, checksum, "Checksum: 0x%04x [correct]", checksum);
		hexabus_crc_tree = proto_item_add_subtree(ti, ett_hexabus_crc);
		ti = proto_tree_add_boolean(hexabus_crc_tree, hf_hexabus_crc_good, tvb,
				tvb_length(tvb) - 2, 2, TRUE);
		PROTO_ITEM_SET_GENERATED(ti);
		ti = proto_tree_add_boolean(hexabus_crc_tree, hf_hexabus_crc_bad, tvb,
				tvb_length(tvb) - 2, 2, FALSE);
		PROTO_ITEM_SET_GENERATED(ti);
	} else {
		ti = proto_tree_add_uint_format(hexabus_tree, hf_hexabus_crc, tvb, tvb_length(tvb)-2, 2, checksum, "Checksum: 0x%04x [incorrect, should be 0x%04x]", checksum, crc);
		hexabus_crc_tree = proto_item_add_subtree(ti, ett_hexabus_crc);
		ti = proto_tree_add_boolean(hexabus_crc_tree, hf_hexabus_crc_good, tvb,
				tvb_length(tvb) - 2, 2, FALSE);
		PROTO_ITEM_SET_GENERATED(ti);
		ti = proto_tree_add_boolean(hexabus_crc_tree, hf_hexabus_crc_bad, tvb,
				tvb_length(tvb) - 2, 2, TRUE);
		PROTO_ITEM_SET_GENERATED(ti);
		expert_add_info_format(pinfo, ti, &ei_hexabus_bad_checksum, "Bad checksum");
		col_append_fstr(pinfo->cinfo, COL_INFO, " [HEXABUS CHECKSUM INCORRECT]");
	}

	/* If this protocol has a sub-dissector call it here, see section 1.8 */

	/* Return the amount of data this dissector was able to dissect */
	return tvb_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_hexabus(void)
{
	expert_module_t* expert_hexabus;
	module_t *hexabus_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_hexabus_type,
			{ "Packet type",           "hexabus.type",
			FT_UINT8, BASE_HEX, hf_hexabus_type_names, 0x0,
			"Packet type", HFILL }
		},
		{ &hf_hexabus_flags,
			{ "Flags", "hexabus.flags",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Flags", HFILL }
		},
		{ &hf_hexabus_eid,
			{ "Endpoint ID",	          "hexabus.eid",
			FT_UINT8, BASE_HEX, hf_hexabus_eid_names, 0x0,
			"Endpoint ID", HFILL }
		},
		{ &hf_hexabus_dtype,
			{ "Data type",              "hexabus.dtype",
			FT_UINT8, BASE_HEX, hf_hexabus_dtype_names, 0x0,
			"Data type", HFILL }
		},
		{ &hf_hexabus_bool_value,
			{ "Value (Boolean)",         "hexabus.value",
			FT_BOOLEAN, 8, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_uint8_value,
			{ "Value (Unsigned 8 bit integer)", "hexabus.value",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_uint32_value,
			{ "Value (Unsigned 32 bit integer)", "hexabus.value",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_datetime_value,
			{ "Value (Date and Time)", "hexabus.value",
			FT_UINT64, BASE_HEX, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_datetime_value_hour,
			{ "Hour", "hexabus.value.hour",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_datetime_value_minute,
			{ "Minute", "hexabus.value.minute",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_datetime_value_second,
			{ "Second", "hexabus.value.second",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_datetime_value_day,
			{ "Day", "hexabus.value.day",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_datetime_value_month,
			{ "Month", "hexabus.value.month",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_datetime_value_year,
			{ "Year", "hexabus.value.year",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_datetime_value_weekday,
			{ "Weekday", "hexabus.value.weekday",
			FT_UINT8, BASE_DEC, hf_hexabus_weekday_names, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_float_value,
			{ "Value (32 bit floating point)", "hexabus.value",
			FT_FLOAT, BASE_NONE, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_128string_value,
			{ "Value (128 char fixed length string)", "hexabus.value",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Value", HFILL }
		},
		{ &hf_hexabus_timestamp_value,
			{ "Value (timestamp)", "hexabus.value",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Value", HFILL }
		},
		{
			&hf_hexabus_endpoint,
			{ "Endpoint description", "hexabus.endpoint",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Description of the requested Endpoint", HFILL }
		},
		{
			&hf_hexabus_error,
			{ "Error code", "hexabus.error",
			FT_UINT8, BASE_HEX, hf_hexabus_error_names, 0x0,
			"Error", HFILL }
		},
		{
			&hf_hexabus_crc,
			{ "CRC", "hexabus.crc",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"CRC", HFILL }
		},
		{
			&hf_hexabus_crc_good,
			{ "Good Checksum", "udp.crc_good",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"True: CRC matches packet content; False: CRC doesn't match packet content or not checked", HFILL }
		},
		{
			&hf_hexabus_crc_bad,
			{ "Bad Checksum", "udp.crc_bad",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"True: CRC doesn't match packet content or not checked; False: CRC matches packet content", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_hexabus,
		&ett_hexabus_datetime,
		&ett_hexabus_flags,
		&ett_hexabus_crc
	};

/* Register the protocol name and description */
	proto_hexabus = proto_register_protocol("Hexabus",
	    "Hexabus", "hexabus");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_hexabus, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

/* Register preferences module (See Section 2.6 for more on preferences) */
/* (Registration of a prefs callback is not required if there are no     */
/*  prefs-dependent registration functions (eg: a port pref).            */
/*  See proto_reg_handoff below.                                         */
/*  If a prefs callback is not needed, use NULL instead of               */
/*  proto_reg_handoff_hexabus in the following).                     */
	hexabus_module = prefs_register_protocol(proto_hexabus,
	    proto_reg_handoff_hexabus);

/* Register preferences module under preferences subtree.
   Use this function instead of prefs_register_protocol if you want to group
   preferences of several protocols under one preferences subtree.
   Argument subtree identifies grouping tree node name, several subnodes can be
   specified usign slash '/' (e.g. "OSI/X.500" - protocol preferences will be
   accessible under Protocols->OSI->X.500-><Hexabus> preferences node.
*/
  /*hexabus_module = prefs_register_protocol_subtree(const char *subtree,
       proto_hexabus, proto_reg_handoff_hexabus);*/

/* Register a sample preference */
	prefs_register_bool_preference(hexabus_module, "show_hex",
	     "Display numbers in Hex",
	     "Enable to display numerical values in hexadecimal.",
	     &gPREF_HEX);

/* Register a sample port preference   */
	prefs_register_uint_preference(hexabus_module, "udp.port", "hexabus UDP Port",
	     " hexabus UDP port if other than the default",
	     10, &gPORT_PREF);

	expert_hexabus = expert_register_protocol(proto_hexabus);
	expert_register_field_array(expert_hexabus, ei, array_length(ei));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these
   routines and create the code that calls these routines.

   If this function is registered as a prefs callback (see prefs_register_protocol
   above) this function is also called by preferences whenever "Apply" is pressed;
   In that case, it should accommodate being called more than once.

   This form of the reg_handoff function is used if if you perform
   registration functions which are dependent upon prefs. See below
   for a simpler form  which can be used if there are no
   prefs-dependent registration functions.
*/
void
proto_reg_handoff_hexabus(void)
{
	static gboolean initialized = FALSE;
        static dissector_handle_t hexabus_handle;
        static int currentPort;

	if (!initialized) {

/*  Use new_create_dissector_handle() to indicate that dissect_hexabus()
 *  returns the number of bytes it dissected (or 0 if it thinks the packet
 *  does not belong to Hexabus).
 */
		hexabus_handle = new_create_dissector_handle(dissect_hexabus,
								 proto_hexabus);
		initialized = TRUE;
	} else {

 		/*
		  If you perform registration functions which are dependent upon
		  prefs the you should de-register everything which was associated
		  with the previous settings and re-register using the new prefs
		  settings here. In general this means you need to keep track of
		  the hexabus_handle and the value the preference had at the time
		  you registered.  The hexabus_handle value and the value of the
		  preference can be saved using local statics in this
		  function (proto_reg_handoff).
		*/

		dissector_delete_uint("udp.port", currentPort, hexabus_handle);
	}

	currentPort = gPORT_PREF;

	dissector_add_uint("udp.port", currentPort, hexabus_handle);

}

#if 0
/* Simple form of proto_reg_handoff_hexabus which can be used if there are
   no prefs-dependent registration function calls.
 */

void
proto_reg_handoff_hexabus(void)
{
	dissector_handle_t hexabus_handle;

/*  Use new_create_dissector_handle() to indicate that dissect_hexabus()
 *  returns the number of bytes it dissected (or 0 if it thinks the packet
 *  does not belong to Hexabus).
 */
	hexabus_handle = new_create_dissector_handle(dissect_hexabus,
							 proto_hexabus);
	dissector_add_uint("PARENT_SUBFIELD", ID_VALUE, hexabus_handle);
}
#endif

