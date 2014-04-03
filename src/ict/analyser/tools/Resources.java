package ict.analyser.tools;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

public class Resources {

	private ResourceBundle resources;

	private String myName;

	InetAddress localAddress;

	public Resources(String name) {
		myName = name;

		try {
			resources = ResourceBundle.getBundle("etc.config." + myName,
					Locale.getDefault());
		} catch (MissingResourceException exc) {
			exc.printStackTrace();
		}
	}

	public ResourceBundle getResourceBundle() {
		return resources;
	}

	public void error(String str) {
		System.err.println(myName + ".properties: " + str);
		System.exit(2);
	}

	public String getNull(String key) {
		String ret;

		try {
			ret = resources.getString(key);
		} catch (MissingResourceException mre) {
			ret = null;
		}

		return ret;
	}

	public String get(String key) {
		String ret = getNull(key);

		// if (ret == null)
		// error("key `" + key + "' not found");

		return ret;
	}

	public String getAndTrim(String key) {
		String re = get(key);
		int len = re.length();
		String ret = new String();
		boolean space = true;

		for (int i = 0; i < len; i++) {
			char ch = re.charAt(i);

			if (Character.isWhitespace(ch)) {
				if (!space) {
					space = true;
					ret += ' ';
				}
			} else {
				ret += ch;
				space = false;
			}
		}

		return ret;
	}

	public char getChar(String key) {
		String str = getNull(key);

		if (str == null) {
			error("key `" + key + "' not found");
		}

		if (str.length() != 1) {
			error("key `" + key + "' must have one char value");
		}

		return str.charAt(0);
	}

	/**
	 * �жϡ����롱�����ǲ���true
	 * 
	 * @param key
	 *            �Ⱥ���ߵ��ַ�
	 * @return ���ͺ��booleanֵ
	 */
	public boolean isTrue(String key) {
		String val = get(key);

		if (val.equalsIgnoreCase("yes") || val.equalsIgnoreCase("on")
				|| val.equalsIgnoreCase("true")
				|| val.equalsIgnoreCase("rulez")
				|| val.equalsIgnoreCase("enable")) {
			return true;
		}

		if (val.equalsIgnoreCase("no") || val.equalsIgnoreCase("off")
				|| val.equalsIgnoreCase("false")
				|| val.equalsIgnoreCase("suxx")
				|| val.equalsIgnoreCase("disable")) {
			return false;
		}

		error("key `"
				+ key
				+ "' must be a logical value: yes/on/true/enable/rulez or no/off/false/disable/suxx ");
		return false;
	}

	public int integer(String key) {
		try {
			String v = get(key);
			if (v != null) {
				return Integer.parseInt(v);
			}
		} catch (NumberFormatException exc) {
			error("key `" + key + "' must be a integer value");
		}

		return 0;
	}

	public int getInterval(String key) {
		int mul = 0;
		String val = get(key);
		int len = val.length() - 1;

		if (len < 0) {
			error("key `" + key + "' cannot be empty");
		}

		char ch = val.charAt(len);

		if (ch == 'h' || ch == 'H') {
			mul = 3600;
		} else if (ch == 'm' || ch == 'M') {
			mul = 60;
		} else if (ch == 's' || ch == 'S') {
			mul = 1;
		}

		if (mul != 0 && len > 0) {
			val = val.substring(0, len);
		} else {
			mul = 1;
		}

		try {
			return Integer.parseInt(val) * mul;
		} catch (NumberFormatException exc) {
			error("key `" + key + "' must be a interval value");
		}

		return 0;
	}

	public String getMyHostName() {
		String ret = null;

		try {
			if (localAddress == null) {
				localAddress = InetAddress.getLocalHost();
			}

			StringTokenizer st = new StringTokenizer(localAddress.toString(),
					"/");
			ret = st.nextToken();
		} catch (UnknownHostException e) {
			System.err.println("Unknown localhost address/name");
			System.exit(2);
		}

		return ret;
	}
}
