package ict.analyser.tools;

/*
 * Filename: IPTranslator.java
 * Copyright: ICT (c) 2012-10-19
 * Description: IP地址相关的变换，如将ip转换成整数，反转换，ip和mask得到prefix等。
 * Author: 25hours
 */

/**
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-10-19
 */
public class IPTranslator {

	/**
	 * 根据ip地址和子网掩码得到网段对应long
	 * 
	 * @param ip
	 *            ip地址
	 * @param mask
	 *            子网掩码
	 * @return 网段对应long
	 */
	public static long calLongPrefix(String ip, String mask) {
		String[] ipseg = ip.split("\\.");
		String[] seg = mask.split("\\.");
		long result;
		long i1, i2, i3, i4, j1, j2, j3, j4;
		i1 = Long.parseLong(ipseg[0]);
		i2 = Long.parseLong(ipseg[1]);
		i3 = Long.parseLong(ipseg[2]);
		i4 = Long.parseLong(ipseg[3]);
		j1 = Long.parseLong(seg[0]);
		j2 = Long.parseLong(seg[1]);
		j3 = Long.parseLong(seg[2]);
		j4 = Long.parseLong(seg[3]);
		result = ((i1 & j1) << 24) + ((i2 & j2) << 16) + ((i3 & j3) << 8)
				+ (i4 & j4);
		return result;
	}

	/**
	 * 将ip转化成long型数。
	 * 
	 * @param ip
	 *            要转化成int型的ip地址
	 * @return 转化后的int型ip
	 */
	public static long calIPtoLong(String ip) {
		String[] ipseg = ip.split("\\.");
		long result = 0;
		long i1, i2, i3, i4;
		i1 = Long.parseLong(ipseg[0]);
		i2 = Long.parseLong(ipseg[1]);
		i3 = Long.parseLong(ipseg[2]);
		i4 = Long.parseLong(ipseg[3]);
		result = (i1 << 24) + (i2 << 16) + (i3 << 8) + i4;
		return result;
	}

	/**
	 * 将long型ip转换成String型
	 * 
	 * @param intIp
	 *            int型ip
	 * @return 字符串型
	 */
	public static String calLongToIp(long intIp) {
		String ipStr = "";
		// 直接右移24位
		ipStr += String.valueOf((intIp >>> 24)) + ".";
		// 将高8位置0，然后右移16位
		ipStr += String.valueOf((intIp & 0x00FFFFFF) >>> 16) + ".";
		// 将高16位置0，然后右移8位
		ipStr += String.valueOf((intIp & 0x0000FFFF) >>> 8) + ".";
		// 将高24位置0
		ipStr += String.valueOf((intIp & 0x000000FF));
		return ipStr;
	}

	public static String longToIP(long longIP)
	// 将10进制整数形式转换成127.0.0.1形式的IP地址，在命令提示符下输入ping 3396362403L
	{
		StringBuffer sb = new StringBuffer("");
		sb.append(String.valueOf(longIP >>> 24));// 直接右移24位
		sb.append(".");
		sb.append(String.valueOf((longIP & 0x00FFFFFF) >>> 16)); // 将高8位置0，然后右移16位
		sb.append(".");
		sb.append(String.valueOf((longIP & 0x0000FFFF) >>> 8));
		sb.append(".");
		sb.append(String.valueOf(longIP & 0x000000FF));
		sb.append(".");
		return sb.toString();
	}

	/**
	 * 根据ip和mask计算前缀
	 * 
	 * @param ip
	 *            ip地址
	 * @param mask
	 *            掩码
	 * @return 前缀字符串
	 */
	public static String calPrefix(String ip, String mask) {
		String[] ipseg = ip.split("\\.");
		String[] seg = mask.split("\\.");
		String result = "";
		long i1, i2, i3, i4, j1, j2, j3, j4;
		i1 = Long.parseLong(ipseg[0]);
		i2 = Long.parseLong(ipseg[1]);
		i3 = Long.parseLong(ipseg[2]);
		i4 = Long.parseLong(ipseg[3]);
		j1 = Long.parseLong(seg[0]);
		j2 = Long.parseLong(seg[1]);
		j3 = Long.parseLong(seg[2]);
		j4 = Long.parseLong(seg[3]);
		result = (i1 & j1) + "." + (i2 & j2) + "." + (i3 & j3) + "."
				+ (i4 & j4);
		return result;
	}

	/**
	 * 得到mask后的零的个数,会在移位查找prefix所属设备id的时候用到
	 * 
	 * @param mask
	 *            long型子网掩码
	 * @return mask后零的个数
	 */
	public static int getZeroNumInMask(long mask) {
		int num = 0;
		if (mask == 0) {
			return 32;
		}
		for (int i = 63; i > 0; i--) {
			if (((mask << i) - 0) == 0) {
				num++;
			} else {
				break;
			}
		}
		return num;
	}

	/**
	 * 根据long型ip和mask中1的个数得到long型prefix，会在移位查找prefix所属设备id的时候用到
	 * 
	 * @param ip
	 * @param len
	 * @return long型prefix
	 */
	public static String getChangedPrefix(String ip, String mask) {
		long ipLong = calIPtoLong(ip);
		long maskLong = calIPtoLong(mask);

		maskLong = maskLong << 1;
		long prefix = ipLong & maskLong;
		return calLongToIp(prefix);
	}

	/**
	 * 
	 * 
	 * @param srcAddr
	 * @param srcMask
	 * @return
	 */
	public static long calLongPrefix(long address, byte mask) {
		long dmask = ~((1 << (32 - (mask & 0xff))) - 1);
		long prefix = mask <= 0 || mask >= 32 ? address : address & dmask;
		return prefix;
	}
}
