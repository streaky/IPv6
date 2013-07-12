<?php

/**
 * 
 * Copyright 2013 Martin Nicholls
 * 
 * Contains (fairly large) portions of code Copyright (C) 2009, 2011 Ray Patrick Soucy
 * - http://www.soucy.org/project/inet6/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

class ipv6Exception extends \Exception {}

class ipv6 {

	public static function expand($addr) {
		/* Check if there are segments missing, insert if necessary */
		if(strpos($addr, '::') !== false) {
			$part = explode('::', $addr);
			$part[0] = explode(':', $part[0]);
			$part[1] = explode(':', $part[1]);
			$missing = array();
			for($i = 0; $i < (8 - (count($part[0]) + count($part[1]))); $i++) {
				array_push($missing, '0000');
			}
			$missing = array_merge($part[0], $missing);
			$part = array_merge($missing, $part[1]);
		} else {
			$part = explode(":", $addr);
		}
		/* Pad each segment until it has 4 digits */
		foreach($part as &$p) {
			while(strlen($p) < 4) {
				$p = '0' . $p;
			}
		}
		/* Join segments */
		$result = implode(':', $part);
		/* Quick check to make sure the length is as expected */
		if(strlen($result) == 39) {
			return $result;
		} else {
			// something weird happened
			throw new ipv6Exception("Final address length is invalid");
		}
	}
	
	public static function compress($address) {
		$result = inet_ntop(inet_pton($address));
		return $result;
	}
	
	public static function prefixToMask($prefix) {
		
		if(!function_exists("gmp_init")) {
			throw new ipv6Exception("This function requires the GMP extension to be installed");
		}
		
		$result = "";
		
		$prefix = intval($prefix);
		if ($prefix < 0 || $prefix > 128) {
			throw new ipv6Exception("Invalid prefix length");
		}
		$mask = '0b';
		for ($i = 0; $i < $prefix; $i++) {
			$mask .= '1';
		}
		for ($i = strlen($mask) - 2; $i < 128; $i++) {
			$mask .= '0';
		}
		$mask = gmp_strval(gmp_init($mask), 16);
		for ($i = 0; $i < 8; $i++) {
			$result .= substr($mask, $i * 4, 4);
			if ($i != 7) {
				$result .= ':';
			}
		}
		return self::compress($result);
	}

	/**
	 *
	 * @param string $cidr
	 *
	 * @return ipv6_range
	 */
	public static function cidrToRange($cidr) {
		
		if(!function_exists("gmp_init")) {
			throw new ipv6Exception("This function requires the GMP extension to be installed");
		}
		
		$cidr = explode("/", $cidr);
		
		if(count($cidr) != 2) {
			throw new ipv6Exception("Invalid range CIDR");
		}
		
		$addr = $cidr[0];
		$prefix = (int) $cidr[1];
		
		$start_result = $end_result = "";
		
		$size = 128 - $cidr[1];
		$addr = gmp_init('0x' . str_replace(':', '', self::expand($addr)));
		$mask = gmp_init('0x' . str_replace(':', '', self::expand(self::prefixToMask($prefix))));
		$prefix = gmp_and($addr, $mask);
		$start = gmp_strval(gmp_add($prefix, '0x1'), 16);
		$end = '0b';
		for($i = 0; $i < $size; $i++) {
			$end .= '1';
		}
		$end = gmp_strval(gmp_add($prefix, gmp_init($end)), 16);
		for($i = 0; $i < 8; $i++) {
			$start_result .= substr($start, $i * 4, 4);
			if($i != 7) {
				$start_result .= ':';
			}
		} // for
		for($i = 0; $i < 8; $i++) {
			$end_result .= substr($end, $i * 4, 4);
			if($i != 7) {
				$end_result .= ':';
			}
		} // for
		$result = new ipv6_range(self::compress($start_result), self::compress($end_result));
		return $result;
	}

	public static function inRange($cidr, $target) {
		
		$range = self::cidrToRange($cidr);
		$address = inet_pton($target);
		if((strlen($address) == strlen(inet_pton($range->start))) && ($address >= inet_pton($range->start) && $address <= inet_pton($range->end))) {
		    return true;
		}
		return false;
	}

	public static function getPtrName($address) {
		$address = self::expand($address);
		$address = str_replace(":", "", $address);
		$address = str_split($address);
		$address = implode(".", array_reverse($address)) . ".ip6.arpa";
		return $address;
	}
}

class ipv6_range {

	public $start;

	public $end;

	public function __construct($start, $end) {
		$this->start = $start;
		$this->end = $end;
	}
}
