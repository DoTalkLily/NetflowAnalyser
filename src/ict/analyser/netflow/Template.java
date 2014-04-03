package ict.analyser.netflow;

import ict.analyser.collector.Params;
import ict.analyser.tools.Utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Properties;

/**
 * 
 * 
 * 
 * @author 25hours
 * @version 1.0, 2012-11-19
 */
public class Template {

	private int templateId = 0;// 妯℃澘id

	private int wholeOffset = 0;// 妯℃澘鐨勬墍鏈夊睘鎬х殑offset鍜�

	private int samplingRate = 1;// 閲囨牱鐜�

	private String routerIp = null;// 璺敱鍣╥p

	final static int MAX_TYPE = 93;// 妯℃澘涓睘鎬у搴旂殑鏈�ぇ鍊间笂闄�

	private int[] lenOftypes = new int[MAX_TYPE];// 妯℃澘涓睘鎬х殑闀垮害

	private int[] offsetOftypes = new int[MAX_TYPE];// 妯℃澘涓睘鎬х殑浣嶇Щ

	private Properties property = new Properties();// 灏嗘ā鏉挎牸寮忔枃浠朵腑鐨勯敭鍊煎杞藉叆

	static String templatePath = Params.path + "\\etc\\templates\\";// 妯℃澘鏂囦欢瀛樺偍璺緞

	// 娉�!!锛氬湪linux涓�瑕佸啓鎴愶細 Params.path + "/etc/templates/";

	/**
	 * 浠庢枃浠跺悕寰楀埌璺敱鍣╥p鍜宼emplate id锛屾枃浠跺悕鏍煎紡 x.x.x.x_templateId.properties锛岀劧鍚庡垵濮嬪寲妯℃澘
	 * 
	 * @param fileName
	 */
	public Template(String fileName) {

		int beginIdx = fileName.lastIndexOf("\\");

		if (beginIdx < 0) {
			beginIdx = 0;
		} else {
			beginIdx += 1;
		}

		String routerIp = fileName.trim().substring(beginIdx,
				fileName.indexOf("_"));
		String templateIdStr = fileName.trim().substring(
				fileName.indexOf("_") + 1, fileName.lastIndexOf("."));

		int tid = Integer.parseInt(templateIdStr);

		makeTemplate(routerIp, tid);
	}

	/**
	 * 鐢ㄥ皢flowset涓殑byte鎻愬彇鎴愪竴涓猼emplate锛屽垵濮嬪寲鍙橀噺骞跺皢template鍐欏叆鏂囦欢
	 * 
	 * @param routerIp
	 * @param flowset
	 * @param templateOffset
	 */
	public Template(String routerIp, byte[] flowset, int templateOffset) {

		int tid = (int) Utils.byte2long(flowset, templateOffset, 2);

		if (tid < 0 || tid > 255) {// 0-255 reserved for flowset IDs
			int fieldCnt = (int) Utils
					.byte2long(flowset, templateOffset + 2, 2);
			Properties property = new Properties();
			templateOffset += 4;

			// int dataFlowSetOffset = 4;// after the flowSetID and length

			int dataFlowSetOffset = 0;

			for (int idx = 0; idx < fieldCnt; idx++) {
				int typeName = (int) Utils
						.byte2long(flowset, templateOffset, 2);
				templateOffset += 2;
				int typeLen = (int) Utils.byte2long(flowset, templateOffset, 2);
				templateOffset += 2;

				if (typeName < MAX_TYPE && typeName > 0) {
					property.setProperty(new Integer(typeName).toString(),
							new Integer(dataFlowSetOffset).toString());
					this.offsetOftypes[typeName] = dataFlowSetOffset;
					this.lenOftypes[typeName] = typeLen;
				}
				dataFlowSetOffset += typeLen;
			}
			if (property.size() <= 0) {// if nothing is inputted
				System.err.println("No field type in the template");
			}

			property.setProperty(new Integer(-1).toString(), new Integer(
					dataFlowSetOffset).toString());
			wholeOffset = dataFlowSetOffset;
			setRouterIp(routerIp);
			templateId = tid;
//			this.makeTemplate(routerIp, property, tid);
		} else {
			System.err.println("Template id is illegal");
		}
	}

	/**
	 * 鏍规嵁璺敱鍣╥p 鍜宼empate id 杞藉叆涓�釜妯℃澘
	 * 
	 * @param routerIp
	 * @param tid
	 */
	public Template(String routerIp, int tid) {
		makeTemplate(routerIp, tid);
	}

	/**
	 * 浠庢枃浠朵腑杞藉叆妯℃澘
	 * 
	 * @param routerIp
	 * @param tid
	 */
	@SuppressWarnings("rawtypes")
	public void makeTemplate(String routerIp, int tid) {

		this.routerIp = routerIp;
		this.templateId = tid;

			try {
				InputStream is=this.getClass().getResourceAsStream("/etc/templates/"+routerIp+"_"+tid+".properties"); 
				property.load(is);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

		wholeOffset = Integer.parseInt(property.getProperty("-1"));
		if (property != null) {
			for (Enumeration theKeys = property.propertyNames(); theKeys
					.hasMoreElements();) {
				String key = theKeys.nextElement().toString();
				int typeName = Integer.parseInt(key);
				if (typeName > 0 && typeName < Template.MAX_TYPE) {
					int offset = Integer.parseInt(property.getProperty(key));
					this.offsetOftypes[typeName] = offset;
					this.lenOftypes[typeName] = wholeOffset - offset;
				}
			}
			for (Enumeration theKeys = property.propertyNames(); theKeys
					.hasMoreElements();) {
				String key = theKeys.nextElement().toString();
				int typeName = Integer.parseInt(key);
				if (typeName > 0 && typeName < Template.MAX_TYPE) {
					if (typeName == 11) {
						System.out.println("");
					}
					for (int i = 0; i < offsetOftypes.length; i++) {
						if (offsetOftypes[i] >= 0
								&& (offsetOftypes[i] - offsetOftypes[typeName] > 0)
								&& (offsetOftypes[i] - offsetOftypes[typeName] < lenOftypes[typeName])) {
							lenOftypes[typeName] = offsetOftypes[i]
									- offsetOftypes[typeName];
						}
					}
				}
			}
		}
	}

	/**
	 * 灏唗emplate 鍐欏叆鏂囦欢
	 * 
	 * @param routerIp
	 * @param properties
	 * @param tid
	 */

	public void makeTemplate(String routerIp, Properties properties, int tid) {
		property = properties;
		templateId = tid;
		setRouterIp(routerIp);
		if (property != null) {
			File propFile = new File(templatePath + routerIp + "_" + tid
					+ ".properties");

			if (propFile.exists()) {
				propFile.delete();
			}
			OutputStream propOut;
			try {
				propOut = new FileOutputStream(propFile);
				property.store(propOut, "template of " + tid + " " + routerIp);
				propOut.flush();
				propOut.close();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

		} else {
			System.err.println("Template is null");
		}
	}

	/**
	 * 杩斿洖涓�釜type name 鍦╰emplate涓殑鍋忕Щ
	 * 
	 * @param typeName
	 * @return
	 */
	public int getTypeOffset(int typeName) {
		if (typeName > 0 && typeName < MAX_TYPE) {
			if (this.offsetOftypes[typeName] == 0) {
				String value = this.property.getProperty(new Integer(typeName)
						.toString());
				if (value != null) {
					offsetOftypes[typeName] = Integer.parseInt(value);
				}
			}
			return offsetOftypes[typeName];
		} else if (typeName == -1) {
			return wholeOffset;
		} else {
			return -1;
		}
	}

	/**
	 * 鏍规嵁灞炴�鍚嶅緱鍒板睘鎬ч暱搴�
	 * 
	 * @param typeName
	 * @return
	 */
	public int getTypeLen(int typeName) {
		if (typeName > 0 && typeName < MAX_TYPE) {
			return lenOftypes[typeName];
		}
		return 0;
	}

	/**
	 * @return Returns the templateId.
	 */
	public int getTemplateId() {
		return templateId;
	}

	/**
	 * @param templateId
	 *            The templateId to set.
	 */
	public void setTemplateId(int templateId) {
		this.templateId = templateId;
	}

	/**
	 * @return Returns the samplingRate.
	 */
	public int getSamplingRate() {
		return samplingRate;
	}

	/**
	 * @param samplingRate
	 *            The samplingRate to set.
	 */
	public void setSamplingRate(int samplingRate) {
		this.samplingRate = samplingRate;
	}

	/**
	 * @return Returns the wholeOffset.
	 */
	public int getWholeOffset() {
		return wholeOffset;
	}

	/**
	 * @param wholeOffset
	 *            The wholeOffset to set.
	 */
	public void setWholeOffset(int wholeOffset) {
		this.wholeOffset = wholeOffset;
	}

	/**
	 * @return Returns the routerIp.
	 */
	public String getRouterIp() {
		return routerIp;
	}

	/**
	 * @param routerIp
	 *            The routerIp to set.
	 */
	public void setRouterIp(String routerIp) {
		this.routerIp = routerIp;
	}
}
