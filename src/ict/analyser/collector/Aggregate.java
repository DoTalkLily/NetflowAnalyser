package ict.analyser.collector;

import ict.analyser.netflow.Netflow;
import ict.analyser.netflow.V5_Packet;
import ict.analyser.netflow.V9_Packet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

public class Aggregate {

	private int count = 0;
	private static int maxmum = 10000000;
	private HashMap<String, Netflow> allFlows = null;

	public Aggregate() {
		allFlows = new HashMap<String, Netflow>();
	}

	public void process(final V5_Packet packet) {

		if (count > maxmum) {// 最多能存的条数，多余这些则清空
			count = 0;
			this.allFlows.clear();
			return;
		}

		ArrayList<Netflow> flows = packet.getFlows();
		Iterator<Netflow> iterator = flows.iterator();
		Netflow flowToAdd = null;
		Netflow flowFound = null;
		String key = null;
		while (iterator.hasNext()) {
			flowToAdd = iterator.next();
			key = flowToAdd.getKey();

			flowFound = this.allFlows.get(key);

			if (flowFound == null) {
				count++;
				this.allFlows.put(key, flowToAdd);
				flowToAdd.getDetail();
			} else {
				flowFound.addOctets(flowToAdd.getdOctets());
			}
		}

	}

	public void process(final V9_Packet packet) {

		if (count > maxmum) {// 最多能存的条数，多余这些则清空
			count = 0;
			this.allFlows.clear();
			return;
		}

		ArrayList<Netflow> flows = packet.getNormalFlows();
		Iterator<Netflow> iterator = flows.iterator();
		Netflow flowToAdd = null;
		Netflow flowFound = null;

		String key = null;
		while (iterator.hasNext()) {
			flowToAdd = iterator.next();
			key = flowToAdd.getKey();
			flowFound = this.allFlows.get(key);
			if (flowFound == null) {
				count++;
				this.allFlows.put(key, flowToAdd);
				flowToAdd.getDetail();
			} else {
				flowFound.addOctets(flowToAdd.getdOctets());
			}
		}
	}
}
