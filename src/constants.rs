// constants.rs - Sphinx replay tag cache constants.
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.


/// Flush mix key writeback cache every 10 seconds.
pub const MIX_KEY_FLUSH_FREQUENCY: u64 = 10000;

/// Allow a mix expiration grace period of 2 minutes.
pub const MIX_KEY_GRACE_PERIOD: u16 = 2 * 60;
