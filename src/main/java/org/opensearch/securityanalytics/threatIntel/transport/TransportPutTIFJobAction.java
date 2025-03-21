/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.StepListener;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.PutTIFJobAction;
import org.opensearch.securityanalytics.threatIntel.action.PutTIFJobRequest;
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.TIFJobParameter;
import org.opensearch.securityanalytics.threatIntel.service.TIFJobParameterService;
import org.opensearch.securityanalytics.threatIntel.service.TIFJobUpdateService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.threatIntel.common.TIFLockService.LOCK_DURATION_IN_SECONDS;

/**
 * Transport action to create job to fetch threat intel feed data and save IoCs
 */
public class TransportPutTIFJobAction extends HandledTransportAction<PutTIFJobRequest, AcknowledgedResponse> implements SecureTransportAction {
    // TODO refactor this into a service class that creates feed updation job. This is not necessary to be a transport action
    private static final Logger log = LogManager.getLogger(TransportPutTIFJobAction.class);

    private final TIFJobParameterService tifJobParameterService;
    private final TIFJobUpdateService tifJobUpdateService;
    private final TIFLockService lockService;
    private final Settings settings;
    private final ThreadPool threadPool;
    private volatile Boolean filterByEnabled;

    /**
     * Default constructor
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param threadPool the thread pool
     * @param tifJobParameterService the tif job parameter service facade
     * @param tifJobUpdateService the tif job update service
     * @param lockService the lock service
     */
    @Inject
    public TransportPutTIFJobAction(
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ThreadPool threadPool,
            final TIFJobParameterService tifJobParameterService,
            final TIFJobUpdateService tifJobUpdateService,
            final TIFLockService lockService,
            Settings settings
    ) {
        super(PutTIFJobAction.NAME, transportService, actionFilters, PutTIFJobRequest::new);
        this.tifJobParameterService = tifJobParameterService;
        this.tifJobUpdateService = tifJobUpdateService;
        this.lockService = lockService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
    }

    @Override
    protected void doExecute(final Task task, final PutTIFJobRequest request, final ActionListener<AcknowledgedResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }
        this.threadPool.getThreadContext().stashContext();

        try {
            lockService.acquireLock(request.getName(), LOCK_DURATION_IN_SECONDS, ActionListener.wrap(lock -> {
                if (lock == null) {
                    listener.onFailure(
                            new ConcurrentModificationException("another processor is holding a lock on the resource. Try again later")
                    );
                    log.error("another processor is a lock, BAD_REQUEST error", RestStatus.BAD_REQUEST);
                    return;
                }
                try {
                    internalDoExecute(request, lock, listener);
                } catch (Exception e) {
                    log.error("Failed execution to put tif job action", e);
                    lockService.releaseLock(lock, ActionListener.wrap(
                            r -> {
                                log.debug("Released tif job parameter lock with id [{}]", lock.getLockId());
                                listener.onFailure(e);
                            },
                            ex -> {
                                log.error(String.format("Unexpected failure while trying to release lock [%s] for tif job parameter [%s].", lock.getLockId(), request.getName()), ex);
                                listener.onFailure(e);
                            }
                    ));
                }
            }, exception -> {
                listener.onFailure(exception);
                log.error("execution failed", exception);
            }));
        } catch (Exception e) {
            log.error("Failed to acquire lock for job", e);
            listener.onFailure(e);
        }
    }

    /**
     * This method takes lock as a parameter and is responsible for releasing lock
     * unless exception is thrown
     */
    protected void internalDoExecute(
            final PutTIFJobRequest request,
            final LockModel lock,
            final ActionListener<AcknowledgedResponse> listener
    ) {
        StepListener<Void> createIndexStepListener = new StepListener<>();
        createIndexStepListener.whenComplete(v -> {
            try {
                TIFJobParameter tifJobParameter = TIFJobParameter.Builder.build(request);
                tifJobParameterService.saveTIFJobParameter(tifJobParameter, postIndexingTifJobParameter(tifJobParameter, lock, listener));
            } catch (Exception e) {
                listener.onFailure(e);
            }
        }, exception -> {
            log.error("Failed to save tif job parameter", exception);
            lockService.releaseLock(lock, ActionListener.wrap(
                    r -> {
                        log.debug("Released tif job parameter lock with id [{}]", lock.getLockId());
                        listener.onFailure(exception);
                    },
                    ex -> {
                        log.error(String.format("Unexpected failure while trying to release lock [%s] for tif job parameter [%s].", lock.getLockId(), request.getName()), ex);
                        listener.onFailure(exception);
                    }
            ));
        });
        tifJobParameterService.createJobIndexIfNotExists(createIndexStepListener);
    }

    /**
     * This method takes lock as a parameter and is responsible for releasing lock
     * unless exception is thrown
     */
    protected ActionListener<IndexResponse> postIndexingTifJobParameter(
            final TIFJobParameter tifJobParameter,
            final LockModel lock,
            final ActionListener<AcknowledgedResponse> listener
    ) {
        return ActionListener.wrap(
                indexResponse -> {
                    AtomicReference<LockModel> lockReference = new AtomicReference<>(lock);
                    createThreatIntelFeedData(tifJobParameter, lockService.getRenewLockRunnable(lockReference), ActionListener.wrap(
                            threatIntelIndicesResponse -> {
                                if (threatIntelIndicesResponse.isAcknowledged()) {
                                    lockService.releaseLock(lockReference.get(), ActionListener.wrap(
                                            r -> {
                                                log.debug("Released tif job parameter lock with id [{}]", lock.getLockId());
                                                listener.onResponse(new AcknowledgedResponse(true));
                                            },
                                            ex -> {
                                                log.error(String.format("Unexpected failure while trying to release lock [%s] for tif job parameter [%s].", lock.getLockId(), tifJobParameter.getName()), ex);
                                                listener.onFailure(ex);
                                            }
                                    ));
                                } else {
                                    listener.onFailure(new OpenSearchStatusException("creation of threat intel feed data failed", RestStatus.INTERNAL_SERVER_ERROR));
                                }
                            }, listener::onFailure
                    ));
                }, e -> {
                    Exception exception;
                    if (e instanceof VersionConflictEngineException) {
                        log.error("tifJobParameter already exists");
                        exception = new ResourceAlreadyExistsException("tifJobParameter [{}] already exists", tifJobParameter.getName());
                    } else {
                        log.error("Internal server error");
                        exception = e;
                    }
                    lockService.releaseLock(lock, ActionListener.wrap(
                            r -> {
                                log.debug("Released tif job parameter lock with id [{}]", lock.getLockId());
                                listener.onFailure(exception);
                            },
                            ex -> {
                                log.error(String.format("Unexpected failure while trying to release lock [%s] for tif job parameter [%s].", lock.getLockId(), tifJobParameter.getName()), ex);
                                listener.onFailure(exception);
                            }
                    ));
                }
        );
    }

    protected void createThreatIntelFeedData(final TIFJobParameter tifJobParameter, final Runnable renewLock, final ActionListener<ThreatIntelIndicesResponse> listener) {
        if (TIFJobState.CREATING.equals(tifJobParameter.getState()) == false) {
            log.error("Invalid tifJobParameter state. Expecting {} but received {}", TIFJobState.CREATING, tifJobParameter.getState());
            markTIFJobAsCreateFailed(tifJobParameter, listener);
            return;
        }

        try {
            tifJobUpdateService.createThreatIntelFeedData(tifJobParameter, renewLock, listener);
        } catch (Exception e) {
            log.error("Failed to create tifJobParameter for {}", tifJobParameter.getName(), e);
            markTIFJobAsCreateFailed(tifJobParameter, listener);
        }
    }

    private void markTIFJobAsCreateFailed(final TIFJobParameter tifJobParameter, final ActionListener<ThreatIntelIndicesResponse> listener) {
        tifJobParameter.getUpdateStats().setLastFailedAt(Instant.now());
        tifJobParameter.setState(TIFJobState.CREATE_FAILED);
        try {
            tifJobParameterService.updateJobSchedulerParameter(tifJobParameter, listener);
        } catch (Exception e) {
            log.error("Failed to mark tifJobParameter state as CREATE_FAILED for {}", tifJobParameter.getName(), e);
        }
    }
}

