/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.logging.log4j.message.ParameterizedMessage;
import org.junit.Before;
import org.junit.Test;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.commons.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.commons.utils.testUtils.S3ObjectGenerator;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

public class STIX2IOCFetchServiceIT extends ThreatIntelTestCase {
    private String bucket;
    private String region;
    private String roleArn;

    private S3Client s3Client;
    private S3ObjectGenerator s3ObjectGenerator;
    private STIX2IOCFetchService service;

    private String testFeedSourceConfigId;
    private String testIndex;
    private S3ConnectorConfig s3ConnectorConfig;
    private STIX2IOCGenerator stix2IOCGenerator;

    @Before
    public void beforeTest() {
        if (service == null) {
            region = System.getProperty("tests.STIX2IOCFetchServiceIT.region");
            roleArn = System.getProperty("tests.STIX2IOCFetchServiceIT.roleArn");
            bucket = System.getProperty("tests.STIX2IOCFetchServiceIT.bucket");

            s3Client = S3Client.builder()
                    .region(Region.of(region))
                    .build();
            s3ObjectGenerator = new S3ObjectGenerator(s3Client, bucket);

            service = new STIX2IOCFetchService(client, clusterService);
        }
        testFeedSourceConfigId = UUID.randomUUID().toString();
        testIndex = STIX2IOCFeedStore.getFeedConfigIndexName(testFeedSourceConfigId);
        s3ConnectorConfig = new S3ConnectorConfig(bucket, testFeedSourceConfigId, region, roleArn);
    }



    @Test
    public void test_fetchIocs_fetchesIocsCorrectly() throws IOException {
        // Generate test IOCs, and upload them to S3
        int numOfIOCs = 5;
        stix2IOCGenerator = new STIX2IOCGenerator();
        s3ObjectGenerator.write(numOfIOCs, testFeedSourceConfigId, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Create an action listener for the test case
        ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> listener = new ActionListener<>() {
            @Override
            public void onResponse(STIX2IOCFetchService.STIX2IOCFetchResponse stix2IOCFetchResponse) {
                assertEquals(numOfIOCs, stix2IOCFetchResponse.getIocs().size());

                // Query the system index directly for the IOC docs
                List<STIX2IOCDto> iocs = new ArrayList<>();
                try {
                    SearchRequest searchRequest = new SearchRequest(testIndex)
                            .source(SearchSourceBuilder.searchSource().query(QueryBuilders.matchAllQuery()));
                    SearchResponse searchResponse = client.search(searchRequest).get();
                    Arrays.stream(searchResponse.getHits().getHits())
                            .forEach(hit -> {
                                try {
                                    XContentParser xcp = XContentType.JSON.xContent().createParser(
                                            xContentRegistry(),
                                            LoggingDeprecationHandler.INSTANCE,
                                            hit.getSourceAsString());
                                    xcp.nextToken();

                                    STIX2IOCDto ioc = STIX2IOCDto.parse(xcp, hit.getId(), hit.getVersion());
                                    iocs.add(ioc);
                                } catch (Exception e) {
                                    fail("Failed to parse IOC doc from hit during test: " + hit);
                                }
                            });
                    assertEquals(numOfIOCs, iocs.size());
                } catch (Exception e) {
                    fail("Search request failed during test: " + e);
                }

                // Sort all IOC lists for easy comparison
                stix2IOCGenerator.getIocs().sort(Comparator.comparing(STIX2IOC::getName));
                stix2IOCFetchResponse.getIocs().sort(Comparator.comparing(STIX2IOCDto::getName));
                iocs.sort(Comparator.comparing(STIX2IOCDto::getName));

                // Assert expected IOCs are returned
                for (int i = 0; i < stix2IOCGenerator.getIocs().size(); i++) {
                    STIX2IOCGenerator.assertIOCEqualsDTO(stix2IOCGenerator.getIocs().get(i), stix2IOCFetchResponse.getIocs().get(i));
                    STIX2IOCGenerator.assertIOCEqualsDTO(stix2IOCGenerator.getIocs().get(i), iocs.get(i));
                }
            }

            @Override
            public void onFailure(Exception e) {
                fail("STIX2IOCFetchService.fetchIocs failed with error: " + e);
            }
        };

        // Execute the test case
        service.fetchIocs(s3ConnectorConfig, listener);
    }
}
