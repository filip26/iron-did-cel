package com.apicatalog;

public interface RepresentationProvider {

	
	int register();
	
	<T> T representation(String type);

}
