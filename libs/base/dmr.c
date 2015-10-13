/*
 * This file is part of dmrshark.
 *
 * dmrshark is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dmrshark is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dmrshark.  If not, see <http://www.gnu.org/licenses/>.
**/

#include DEFAULTCONFIG

#include "dmr.h"

char *dmr_get_readable_call_type(dmr_call_type_t call_type) {
	switch (call_type) {
		case DMR_CALL_TYPE_PRIVATE: return "private";
		case DMR_CALL_TYPE_GROUP: return "group";
		default: return "unknown";
	}
}

char *dmr_get_readable_sms_type(dmr_sms_type_t sms_type) {
	switch (sms_type) {
		case DMR_SMS_TYPE_NORMAL: return "normal";
		case DMR_SMS_TYPE_MOTOROLA_TMS: return "motorola tms";
		default: return "unknown";
	}
}
