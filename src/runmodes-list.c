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

#include "suricata-common.h"
#include "runmodes-list.h"

extern RunModesList runmodeslist;

int RunmodeIsUnittests(void)
{
    if (RunmodeGetPrimary(&runmodeslist) == RUNMODE_UNITTEST) {
        return 1;
    }
    return 0;
}


int RunmodeSetCurrent(RunModesList *runmodes, enum RunModes run_mode,
                      int increment)
{
    runmodes->run_mode[runmodes->runmodes_cnt] = run_mode;

    if (!increment)
        return 1;

    if (runmodes->runmodes_cnt < RUNMODES_MAX) {
        runmodes->runmodes_cnt++;
    } else {
        return 0;
    }
    return 1;
}

int RunmodeGetCurrent(const RunModesList *runmodes, int index)
{
    return runmodes->run_mode[index];
}

int RunmodeGetNumber(const RunModesList *runmodes)
{
    return runmodes->runmodes_cnt;
}

int RunmodeIsUnknown(const RunModesList *runmodes)
{
    return (runmodes->run_mode[runmodes->runmodes_cnt] == RUNMODE_UNKNOWN);
}

int RunmodeIsSet(const RunModesList *runmodes, const enum RunModes run_mode)
{
    int i;

    for (i = 0; i < runmodes->runmodes_cnt; i++) {
        if (runmodes->run_mode[i] == run_mode) {
            return 1;
        }
    }
    return 0;
}

int RunmodeGetPrimary(const RunModesList *runmodes)
{
    return runmodes->run_mode[0];
}

int RunmodeGetSecondary(const RunModesList *runmodes)
{
    return runmodes->run_mode[1];
}

