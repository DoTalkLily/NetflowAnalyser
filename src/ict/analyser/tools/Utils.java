package ict.analyser.tools;

public abstract class Utils {
	public static byte IntToByte(int i) {
		return (byte) i;
	}

	public static byte[] IntToBytes(int i) {
		byte abyte0[] = new byte[2];
		abyte0[1] = (byte) (0xff & i);
		abyte0[0] = (byte) ((0xff00 & i) >> 8);
		return abyte0;
	}

	public static byte[] IntToBytes4(int i) {
		byte abyte0[] = new byte[4];
		abyte0[3] = (byte) (0xff & i);
		abyte0[2] = (byte) ((0xff00 & i) >> 8);
		abyte0[1] = (byte) ((0xff0000 & i) >> 16);
		abyte0[0] = (byte) ((0xff000000 & i) >> 24);
		return abyte0;
	}

	public static byte[] LongToBytes8(long l) {
		byte abyte0[] = new byte[8];
		abyte0[7] = (byte) (int) (255L & l);
		abyte0[6] = (byte) (int) ((65280L & l) >> 8);
		abyte0[5] = (byte) (int) ((0xff0000L & l) >> 16);
		abyte0[4] = (byte) (int) ((0xff000000L & l) >> 24);
		abyte0[3] = (byte) (int) ((0xff00000000L & l) >> 32);
		abyte0[2] = (byte) (int) ((0xff0000000000L & l) >> 40);
		abyte0[1] = (byte) (int) ((0xff000000000000L & l) >> 48);
		abyte0[0] = (byte) (int) ((0xff00000000000000L & l) >> 56);
		return abyte0;
	}

	public static long Bytes8ToLong(byte abyte0[], int offset) {
		return (255L & (long) abyte0[offset]) << 56
				| (255L & (long) abyte0[offset + 1]) << 48
				| (255L & (long) abyte0[offset + 2]) << 40
				| (255L & (long) abyte0[offset + 3]) << 32
				| (255L & (long) abyte0[offset + 4]) << 24
				| (255L & (long) abyte0[offset + 5]) << 16
				| (255L & (long) abyte0[offset + 6]) << 8
				| (255L & (long) abyte0[offset + 7]);
	}

	public static void LongToBytes4(long l, byte abyte0[]) {
		abyte0[3] = (byte) (int) (255L & l);
		abyte0[2] = (byte) (int) ((65280L & l) >> 8);
		abyte0[1] = (byte) (int) ((0xff0000L & l) >> 16);
		abyte0[0] = (byte) (int) ((0xffffffffff000000L & l) >> 24);
	}

	public static void IntToBytes(int i, byte abyte0[]) {
		abyte0[1] = (byte) (0xff & i);
		abyte0[0] = (byte) ((0xff00 & i) >> 8);
	}

	public static void IntToBytes4(int i, byte abyte0[]) {
		abyte0[3] = (byte) (0xff & i);
		abyte0[2] = (byte) ((0xff00 & i) >> 8);
		abyte0[1] = (byte) ((0xff0000 & i) >> 16);
		abyte0[0] = (byte) (int) ((0xffffffffff000000L & (long) i) >> 24);
	}

	public static int Bytes4ToInt(byte abyte0[], int offset) {
		return (0xff & abyte0[offset]) << 24
				| (0xff & abyte0[offset + 1]) << 16
				| (0xff & abyte0[offset + 2]) << 8 | 0xff & abyte0[offset + 3];
	}

	public static long Bytes4ToLong(byte abyte0[], int offset) {
		return (255L & (long) abyte0[offset + 0]) << 24
				| (255L & (long) abyte0[offset + 1]) << 16
				| (255L & (long) abyte0[offset + 2]) << 8 | 255L
				& (long) abyte0[offset + 3];
	}

	static public final long byte2long(byte[] p, int off, int len) {
		long ret = 0;
		int done = off + len;
		for (int i = off; i < done; i++)
			ret = ((ret << 8) & 0xffffffff) + (p[i] & 0xff);

		return ret;
	}

	public static int int2long(byte[] p, int offset) {
		return (int) byte2long(p, offset, 2);
	}

	static private final String value(long num, String msg) {
		if (num == 0)
			return "";

		return (num == 1 ? "1 " + msg : num + " " + msg + "s") + ", ";
	}

	static public final String uptime(long time) {
		if (time == 0)
			return "0 seconds";

		if (time < 0)
			return time + "(Negative?!)";

		long sec = time % 60;
		long min = (time / 60) % 60;
		long hour = (time / 60 / 60) % 24;
		long day = time / 60 / 60 / 24;

		String ret = value(day, "day") + value(hour, "hour")
				+ value(min, "minute") + value(sec, "second");
		return ret.substring(0, ret.length() - 2);
	}

	static private final char digits[] = { '0', '1', '2', '3', '4', '5', '6',
			'7', '8', '9' };

	static private final String value1(long l) {
		return "" + digits[(int) (l / 10) % 10] + digits[(int) l % 10];
	}

	static public final String uptime_short(long time) {
		if (time == 0)
			return "00:00";

		if (time < 0)
			return time + "(Negative?!)";

		long sec = time % 60;
		long min = (time / 60) % 60;
		long hour = (time / 60 / 60) % 24;
		long day = time / 60 / 60 / 24;

		return value1(day) + '-' + value1(hour) + ':' + value1(min) + ':'
				+ value1(sec);
	}

	static public final String toInterval(long i) {
		if (i < 60)
			return i + "S";

		if (i < 3600)
			return (i / 60) + "M";

		return (i / 3600) + "H";
	}
}
