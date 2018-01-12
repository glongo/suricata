/* Copyright (C) 2007-2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Giuseppe Longo <glongo@stamus-networks.com>
 */

#ifndef __RUNMODES_LIST_H__
#define __RUNMODES_LIST_H__

#include "runmodes.h"

#define RUNMODES_MAX     2

typedef struct RunModesList_ {
    enum RunModes run_mode[RUNMODES_MAX];
    int runmodes_cnt;
} RunModesList;

extern RunModesList runmodestlist;

int RunmodeSetCurrent(RunModesList *runmodes, enum RunModes run_mode,
                      int increment);
int RunmodeGetPrimary(const RunModesList *runmodes);
int RunmodeGetSecondary(const RunModesList *runmodes);
int RunmodeGetNumber(const RunModesList *runmodes);
int RunmodeGetCurrent(const RunModesList *runmodes, int index);
int RunmodeIsUnittests(void);
int RunmodeIsUnknown(const RunModesList *runmodes);
int RunmodeIsSet(const RunModesList *runmodes, const enum RunModes run_mode);

#endif /* __RUNMODES_LIST_H__ */

