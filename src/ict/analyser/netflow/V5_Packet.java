package ict.analyser.netflow;

import ict.analyser.tools.Utils;

import java.util.ArrayList;

/*

 V5 Flow Packet 

 *-------*---------------*------------------------------------------------------*
 | Bytes | Contents      | Description                                          |
 *-------*---------------*------------------------------------------------------*
 | 0-1   | version       | NetFlow export format version number                 |
 *-------*---------------*------------------------------------------------------*
 | 2-3   | count         | Number of flows exported in this packet (1-30)       |
 *-------*---------------*------------------------------------------------------*
 | 4-7   | SysUptime     | Current time in milliseconds since the export device |
 |       |               | booted                                               |
 *-------*---------------*------------------------------------------------------*
 | 8-11  | unix_secs     | Current count of seconds since 0000 UTC 1970         |
 *-------*---------------*------------------------------------------------------*
 | 12-15 | unix_nsecs    | Residual nanoseconds since 0000 UTC 1970             |
 *-------*---------------*------------------------------------------------------*
 | 16-19 | flow_sequence | Sequence counter of total flows seen                 |
 *-------*---------------*------------------------------------------------------*
 | 20    | engine_type   | Type of flow-switching engine                        |
 *-------*---------------*-------------------------------------------Source ID--*
 | 21    | engine_id     | Slot number of the flow-switching engine             |
 *-------*---------------*------------------------------------------------------*
 | 22-23 | reserved      | Unused (zero) bytes                                  |
 *-------*---------------*------------------------------------------------------*

 */

public class V5_Packet {
	private long count = 0;

	private long routerIp = 0;

	private long sys_uptime = 0;

	private long unix_secs = 0;

	private long unix_nsecs = 0;

	private long flow_sequence = 0;

	private long engine_type, engine_id = 0;

	private ArrayList<Netflow> flows = null;

	public static final int V5_Header_Size = 24;

	public static final int V5_Flow_Size = 48;

	/**
	 * 
	 * @param routerIp
	 * @param buf
	 * @param len
	 * @throws DoneException
	 */
	public V5_Packet(long routerIp, byte[] buf, int len) {

		if (len < V5_Header_Size) {
			System.err.println("  * incomplete header *");
			return;
		}

		this.routerIp = routerIp;
		this.count = Utils.byte2long(buf, 2, 2);

		if (this.count <= 0 || len != V5_Header_Size + count * V5_Flow_Size)
			System.err.println("  * corrupted packet " + len + "/" + count
					+ "/" + (V5_Header_Size + count * V5_Flow_Size) + " *");

		this.sys_uptime = Utils.byte2long(buf, 4, 4);
		this.unix_secs = Utils.byte2long(buf, 8, 4);
		this.unix_nsecs = Utils.byte2long(buf, 12, 4);
		this.flow_sequence = Utils.byte2long(buf, 16, 4);
		this.engine_type = buf[20];
		this.engine_id = buf[21];

		this.flows = new ArrayList<Netflow>();

		for (int i = 0, p = V5_Header_Size; i < this.count; i++, p += V5_Flow_Size) {
			Netflow flow;

			flow = new Netflow(routerIp, buf, p);

			if (flow.getSrcAddr() != 0 && flow.getDstAddr() != 0) {
				this.flows.add(flow);
				// flow.getDetail();
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
	 * @return Returns the routerIp.
	 */
	public long getRouterIp() {
		return routerIp;
	}

	/**
	 * @return Returns the sys_uptime.
	 */
	public long getSys_uptime() {
		return sys_uptime;
	}

	/**
	 * @return Returns the unix_secs.
	 */
	public long getUnix_secs() {
		return unix_secs;
	}

	/**
	 * @return Returns the unix_nsecs.
	 */
	public long getUnix_nsecs() {
		return unix_nsecs;
	}

	/**
	 * @return Returns the flow_sequence.
	 */
	public long getFlow_sequence() {
		return flow_sequence;
	}

	/**
	 * @return Returns the engine_type.
	 */
	public long getEngine_type() {
		return engine_type;
	}

	/**
	 * @return Returns the engine_id.
	 */
	public long getEngine_id() {
		return engine_id;
	}

	/**
	 * @return Returns the flows.
	 */
	public ArrayList<Netflow> getFlows() {
		return flows;
	}
}
