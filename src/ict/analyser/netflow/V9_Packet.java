/**
 *
 */
package ict.analyser.netflow;

import ict.analyser.collector.Params;
import ict.analyser.tools.IPTranslator;
import ict.analyser.tools.Utils;
import ict.analyser.tools.Variation;

import java.util.ArrayList;

/*

 V9 Flow Packet 

 *-------*--------------- *------------------------------------------------------*
 | Bytes | Contents       | Description                                          |
 *-------*--------------- *------------------------------------------------------*
 | 0-1   | version        | NetFlow export format version number                 |
 *-------*--------------- *------------------------------------------------------*
 | 2-3   | count          | Number of flows exported in this packet (1-30)       |
 *-------*--------------- *------------------------------------------------------*
 | 4-7   | System Uptime  | Current time in milliseconds since the export device |
 |       |                | booted                                               |
 *-------*--------------- *------------------------------------------------------*
 | 8-11  | UNIX Seconds   | Current count of seconds since 0000 UTC 1970         |
 *-------*--------------- *------------------------------------------------------*
 | 12-15 |Package Sequence| Sequence counter of total flows seen                 |
 *-------*--------------- *------------------------------------------------------*
 | 16-19 | Source ID      | Type of flow-switching engine                        |
 *-------*--------------- *------------------------------------------------------*
 */

public class V9_Packet {

	private long count;

	private long routerIP;

	private long sysUptime, unixSecs, packageSequence;

	private long sourceId;

	private ArrayList<Netflow> normalFlows = null;

	public static final int V9_Header_Size = 20;

	/**
	 * 
	 * 
	 * @param routerIp
	 * @param buf
	 * @param len
	 * @throws DoneException
	 */
	public V9_Packet(long routerIp, byte[] buf, int len) {

		if (len < V9_Header_Size) {
			System.err.println("    * incomplete header *");
			return;
		}

		this.routerIP = routerIp;
		this.count = Utils.byte2long(buf, 2, 2);
		this.sysUptime = Utils.byte2long(buf, 4, 4);
		this.unixSecs = Utils.byte2long(buf, 8, 4);
		this.packageSequence = Utils.byte2long(buf, 12, 4);
		this.sourceId = Utils.byte2long(buf, 16, 4);
		Variation vrat = Variation.getInstance();
		vrat.setVary(this.routerIP, this.sysUptime);
		this.normalFlows = new ArrayList<Netflow>();
		long flowsetLength = 0l;
		long flowsetId = 0l;
		// System.out.println("count :" + count);

		for (int flowsetCounter = 0, packetOffset = V9_Header_Size; flowsetCounter < this.count
				&& packetOffset < len; flowsetCounter++, packetOffset += flowsetLength) {

			flowsetId = Utils.byte2long(buf, packetOffset, 2);
			flowsetLength = Utils.byte2long(buf, packetOffset + 2, 2);

			// System.out.println("flowset id:" + flowsetId + "  length:"
			// + flowsetLength);

			if (flowsetLength == 0) {
				System.err.println("There is a flowset len=0.");
				return;
			}

			String ipStr = IPTranslator.calLongToIp(this.routerIP);

			if (flowsetId == 0) {
				int thisTemplateOffset = packetOffset + 4;
				do {
					long templateId = Utils.byte2long(buf, thisTemplateOffset,
							2);

					long fieldCount = Utils.byte2long(buf,
							thisTemplateOffset + 2, 2);

					System.out.println("template received id = " + templateId);

					if (TemplateManager.getTemplateManager().getTemplate(ipStr,
							(int) templateId) == null
							|| Params.v9TemplateOverwrite) {
						TemplateManager.getTemplateManager().acceptTemplate(
								ipStr, buf, thisTemplateOffset);
					}

					thisTemplateOffset += fieldCount * 4 + 4;

				} while (thisTemplateOffset - packetOffset < flowsetLength);

			} else if (flowsetId > 255) {
				Template tOfData = TemplateManager.getTemplateManager()
						.getTemplate(ipStr, (int) flowsetId); // flowsetId==templateId

				if (tOfData != null) {
					int dataRecordLen = tOfData.getTypeOffset(-1);

					for (int p = packetOffset + 4; (p - packetOffset + dataRecordLen) <= flowsetLength; p += dataRecordLen) {
						Netflow flow = new Netflow(routerIp, buf, p, tOfData);
						normalFlows.add(flow);
					}

				} else { // options packet, should refer to option template, not
					continue;
				}

			} else if (flowsetId == 1) { // options flowset
				continue;
			}
		}
	}

	/**
	 * @return Returns the count.
	 */
	public long getCount() {
		return count;
	}

	/**
	 * @return Returns the routerIP.
	 */
	public long getRouterIP() {
		return routerIP;
	}

	/**
	 * @return Returns the sys_uptime.
	 */
	public long getSys_uptime() {
		return sysUptime;
	}

	/**
	 * @return Returns the unix_secs.
	 */
	public long getUnix_secs() {
		return unixSecs;
	}

	/**
	 * @return Returns the packageSequence.
	 */
	public long getPackageSequence() {
		return packageSequence;
	}

	/**
	 * @return Returns the sourceId.
	 */
	public long getSourceId() {
		return sourceId;
	}

	/**
	 * @return Returns the normalFlows.
	 */
	public ArrayList<Netflow> getNormalFlows() {
		return normalFlows;
	}

}
