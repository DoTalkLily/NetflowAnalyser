package ict.analyser.tools;

public class Variation {
	private static Variation instance = new Variation();
	long[] keys = new long[100];
	long[] values = new long[100];
	int index = 0;

	private Variation() {
	}

	public static Variation getInstance() {
		return instance;
	}

	public synchronized void setVary(long key, long value) {
		int theKeyIdx = findKeyIdx(key);
		if (theKeyIdx == -1) {
			keys[index] = key;
			values[index] = value;
			index++;
		} else {
			// keys[theKeyIdx]=key;
			values[theKeyIdx] = value;
		}
	}

	public synchronized boolean judgeVary(long key, long value) {
		int idx = findKeyIdx(key);
		if (idx != -1) {
			if (values[idx] > value) {
				if (values[idx] - value < 2000000) {
					return true;
				}
			} else {
				if (value - values[idx] < 2000000) {
					return true;
				}
			}
		}
		return false;
	}

	public synchronized boolean judgeVary(long value) {
		for (int idx = 0; idx < index; idx++) {
			if (values[idx] > value) {
				if (values[idx] - value < 2000000) {
					return true;
				}
			} else {
				if (value - values[idx] < 2000000) {
					return true;
				}
			}
		}
		return false;
	}

	private int findKeyIdx(long key) {
		for (int i = 0; i < index; i++) {
			if (keys[i] == key) {
				return i;
			}
		}
		return -1;
	}
}
