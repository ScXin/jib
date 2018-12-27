/*
 * Copyright 2018 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.cloud.tools.jib.plugins.common;

import com.google.cloud.tools.jib.api.Containerizer;
import com.google.cloud.tools.jib.api.DockerDaemonImage;
import com.google.cloud.tools.jib.api.Jib;
import com.google.cloud.tools.jib.api.JibContainerBuilder;
import com.google.cloud.tools.jib.api.RegistryImage;
import com.google.cloud.tools.jib.api.TarImage;
import com.google.cloud.tools.jib.configuration.credentials.Credential;
import com.google.cloud.tools.jib.event.DefaultEventDispatcher;
import com.google.cloud.tools.jib.event.EventDispatcher;
import com.google.cloud.tools.jib.event.events.LogEvent;
import com.google.cloud.tools.jib.filesystem.AbsoluteUnixPath;
import com.google.cloud.tools.jib.frontend.CredentialRetrieverFactory;
import com.google.cloud.tools.jib.frontend.ExposedPortsParser;
import com.google.cloud.tools.jib.frontend.JavaEntrypointConstructor;
import com.google.cloud.tools.jib.frontend.JavaLayerConfigurations;
import com.google.cloud.tools.jib.global.JibSystemProperties;
import com.google.cloud.tools.jib.image.ImageReference;
import com.google.cloud.tools.jib.image.InvalidImageReferenceException;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Verify;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nullable;

/**
 * Configures and provides {@code JibContainerBuilder} for the image building tasks based on raw
 * plugin configuration values and project properties.
 */
public class PluginConfigurationProcessor {

  /** Simple bag of input values of static nature, for convenience in passing around them. */
  @VisibleForTesting
  static class CommonInput {

    private final boolean containerizeWar;
    private final RawConfiguration rawConfiguration;
    private final InferredAuthProvider inferredAuthProvider;
    private final ProjectProperties projectProperties;

    @VisibleForTesting
    CommonInput(
        boolean containerizeWar,
        RawConfiguration rawConfiguration,
        InferredAuthProvider inferredAuthProvider,
        ProjectProperties projectProperties) {
      this.containerizeWar = containerizeWar;
      this.projectProperties = projectProperties;
      this.rawConfiguration = rawConfiguration;
      this.inferredAuthProvider = inferredAuthProvider;
    }
  };

  /**
   * Gets the value of the {@code appRoot} parameter. If the parameter is empty, returns {@link
   * JavaLayerConfigurations#DEFAULT_WEB_APP_ROOT} for WAR projects or {@link
   * JavaLayerConfigurations#DEFAULT_APP_ROOT} for other projects.
   *
   * @param rawConfiguration raw configuration data
   * @param containerizeWar whether to do WAR containerization
   * @return the app root value
   * @throws InvalidAppRootException if {@code appRoot} value is not an absolute Unix path
   */
  public static AbsoluteUnixPath getAppRootChecked(
      RawConfiguration rawConfiguration, boolean containerizeWar) throws InvalidAppRootException {
    String appRoot = rawConfiguration.getAppRoot();
    if (appRoot.isEmpty()) {
      appRoot =
          containerizeWar
              ? JavaLayerConfigurations.DEFAULT_WEB_APP_ROOT
              : JavaLayerConfigurations.DEFAULT_APP_ROOT;
    }
    try {
      return AbsoluteUnixPath.get(appRoot);
    } catch (IllegalArgumentException ex) {
      throw new InvalidAppRootException(appRoot, appRoot, ex);
    }
  }

  public static PluginConfigurationProcessor processCommonConfigurationForDockerDaemonImage(
      RawConfiguration rawConfiguration,
      boolean containerizeWar,
      InferredAuthProvider inferredAuthProvider,
      ProjectProperties projectProperties,
      @Nullable Path dockerExecutable,
      @Nullable Map<String, String> dockerEnvironment,
      HelpfulSuggestions helpfulSuggestions)
      throws InvalidImageReferenceException, MainClassInferenceException, InvalidAppRootException,
          InferredAuthRetrievalException, IOException, InvalidWorkingDirectoryException,
          InvalidContainerVolumeException {
    CommonInput input =
        new CommonInput(containerizeWar, rawConfiguration, inferredAuthProvider, projectProperties);

    ImageReference targetImageReference = getGeneratedTargetDockerTag(input, helpfulSuggestions);
    DockerDaemonImage targetImage = DockerDaemonImage.named(targetImageReference);
    if (dockerExecutable != null) {
      targetImage.setDockerExecutable(dockerExecutable);
    }
    if (dockerEnvironment != null) {
      targetImage.setDockerEnvironment(dockerEnvironment);
    }
    Containerizer containerizer = Containerizer.to(targetImage);

    return processCommonConfiguration(input, containerizer, targetImageReference, false);
  }

  public static PluginConfigurationProcessor processCommonConfigurationForTarImage(
      RawConfiguration rawConfiguration,
      boolean containerizeWar,
      InferredAuthProvider inferredAuthProvider,
      ProjectProperties projectProperties,
      Path tarImagePath,
      HelpfulSuggestions helpfulSuggestions)
      throws InvalidImageReferenceException, MainClassInferenceException, InvalidAppRootException,
          InferredAuthRetrievalException, IOException, InvalidWorkingDirectoryException,
          InvalidContainerVolumeException {
    CommonInput input =
        new CommonInput(containerizeWar, rawConfiguration, inferredAuthProvider, projectProperties);

    ImageReference targetImageReference = getGeneratedTargetDockerTag(input, helpfulSuggestions);
    TarImage targetImage = TarImage.named(targetImageReference).saveTo(tarImagePath);
    Containerizer containerizer = Containerizer.to(targetImage);

    return processCommonConfiguration(input, containerizer, targetImageReference, false);
  }

  public static PluginConfigurationProcessor processCommonConfigurationForRegistryImage(
      RawConfiguration rawConfiguration,
      boolean containerizeWar,
      InferredAuthProvider inferredAuthProvider,
      ProjectProperties projectProperties)
      throws InferredAuthRetrievalException, InvalidImageReferenceException,
          MainClassInferenceException, InvalidAppRootException, IOException,
          InvalidWorkingDirectoryException, InvalidContainerVolumeException {
    Preconditions.checkArgument(rawConfiguration.getToImage().isPresent());

    ImageReference targetImageReference = ImageReference.parse(rawConfiguration.getToImage().get());
    RegistryImage targetImage = RegistryImage.named(targetImageReference);

    EventDispatcher eventDispatcher =
        new DefaultEventDispatcher(projectProperties.getEventHandlers());
    boolean isTargetImageCredentialPresent =
        configureCredentialRetrievers(
            eventDispatcher,
            targetImage,
            targetImageReference,
            PropertyNames.TO_AUTH_USERNAME,
            PropertyNames.TO_AUTH_PASSWORD,
            rawConfiguration.getToAuth(),
            inferredAuthProvider,
            rawConfiguration.getToCredHelper().orElse(null));

    PluginConfigurationProcessor processor =
        processCommonConfiguration(
            new CommonInput(
                containerizeWar, rawConfiguration, inferredAuthProvider, projectProperties),
            Containerizer.to(targetImage),
            targetImageReference,
            isTargetImageCredentialPresent);
    processor.getJibContainerBuilder().setFormat(rawConfiguration.getImageFormat());
    return processor;
  }

  @VisibleForTesting
  static PluginConfigurationProcessor processCommonConfiguration(
      CommonInput input,
      Containerizer containerizer,
      ImageReference targetImageReference,
      boolean isTargetImageCredentialPresent)
      throws InvalidImageReferenceException, MainClassInferenceException, InvalidAppRootException,
          InferredAuthRetrievalException, IOException, InvalidWorkingDirectoryException,
          InvalidContainerVolumeException {
    JibSystemProperties.checkHttpTimeoutProperty();
    JibSystemProperties.checkProxyPortProperty();

    ImageReference baseImageReference = ImageReference.parse(getBaseImage(input));

    EventDispatcher eventDispatcher =
        new DefaultEventDispatcher(input.projectProperties.getEventHandlers());
    if (JibSystemProperties.isSendCredentialsOverHttpEnabled()) {
      eventDispatcher.dispatch(
          LogEvent.warn(
              "Authentication over HTTP is enabled. It is strongly recommended that you do not "
                  + "enable this on a public network!"));
    }

    RegistryImage baseImage = RegistryImage.named(baseImageReference);
    boolean isBaseImageCredentialPresent =
        configureCredentialRetrievers(
            eventDispatcher,
            baseImage,
            baseImageReference,
            PropertyNames.FROM_AUTH_USERNAME,
            PropertyNames.FROM_AUTH_PASSWORD,
            input.rawConfiguration.getFromAuth(),
            input.inferredAuthProvider,
            input.rawConfiguration.getFromCredHelper().orElse(null));

    JibContainerBuilder jibContainerBuilder =
        Jib.from(baseImage)
            .setLayers(
                input.projectProperties.getJavaLayerConfigurations().getLayerConfigurations())
            .setEntrypoint(computeEntrypoint(input))
            .setProgramArguments(input.rawConfiguration.getProgramArguments().orElse(null))
            .setEnvironment(input.rawConfiguration.getEnvironment())
            .setExposedPorts(ExposedPortsParser.parse(input.rawConfiguration.getPorts()))
            .setVolumes(getVolumesSet(input))
            .setLabels(input.rawConfiguration.getLabels())
            .setUser(input.rawConfiguration.getUser().orElse(null));
    getWorkingDirectoryChecked(input).ifPresent(jibContainerBuilder::setWorkingDirectory);
    if (input.rawConfiguration.getUseCurrentTimestamp()) {
      eventDispatcher.dispatch(
          LogEvent.warn(
              "Setting image creation time to current time; your image may not be reproducible."));
      jibContainerBuilder.setCreationTime(Instant.now());
    }

    PluginConfigurationProcessor.configureContainerizer(input, containerizer);

    return new PluginConfigurationProcessor(
        jibContainerBuilder,
        containerizer,
        baseImageReference,
        targetImageReference,
        isBaseImageCredentialPresent,
        isTargetImageCredentialPresent);
  }

  /**
   * Compute the container entrypoint, in this order:
   *
   * <ol>
   *   <li>null (inheriting from the base image), if the user specified value is {@code INHERIT}
   *   <li>the user specified one, if set
   *   <li>for a WAR project, null (it must be inherited from base image)
   *   <li>for a non-WAR project, by resolving the main class
   * </ol>
   *
   * @param input static input including raw configuration data and project properties
   * @return the entrypoint
   * @throws MainClassInferenceException if no valid main class is configured or discovered
   * @throws InvalidAppRootException if {@code appRoot} value is not an absolute Unix path
   */
  @Nullable
  @VisibleForTesting
  static List<String> computeEntrypoint(CommonInput input)
      throws MainClassInferenceException, InvalidAppRootException {
    Optional<List<String>> rawEntrypoint = input.rawConfiguration.getEntrypoint();
    if (rawEntrypoint.isPresent() && !rawEntrypoint.get().isEmpty()) {
      if (input.rawConfiguration.getMainClass().isPresent()
          || !input.rawConfiguration.getJvmFlags().isEmpty()) {
        new DefaultEventDispatcher(input.projectProperties.getEventHandlers())
            .dispatch(
                LogEvent.warn("mainClass and jvmFlags are ignored when entrypoint is specified"));
      }

      if (rawEntrypoint.get().size() == 1 && "INHERIT".equals(rawEntrypoint.get().get(0))) {
        return null;
      }
      return rawEntrypoint.get();
    }

    if (input.containerizeWar) {
      return null;
    }

    AbsoluteUnixPath appRoot = getAppRootChecked(input.rawConfiguration, input.containerizeWar);
    String mainClass =
        MainClassResolver.resolveMainClass(
            input.rawConfiguration.getMainClass().orElse(null), input.projectProperties);
    return JavaEntrypointConstructor.makeDefaultEntrypoint(
        appRoot, input.rawConfiguration.getJvmFlags(), mainClass);
  }

  /**
   * Gets the suitable value for the base image. If the raw base image parameter is null, returns
   * {@code "gcr.io/distroless/java/jetty"} for WAR packaging or {@code "gcr.io/distroless/java"}
   * for non-WAR packaging.
   *
   * @param input static input including raw configuration data and project properties
   * @return the base image
   */
  @VisibleForTesting
  static String getBaseImage(CommonInput input) {
    return input
        .rawConfiguration
        .getFromImage()
        .orElse(input.containerizeWar ? "gcr.io/distroless/java/jetty" : "gcr.io/distroless/java");
  }

  /**
   * Parses the list of raw volumes directories to a set of {@link AbsoluteUnixPath}
   *
   * @param input static input including raw configuration data and project properties
   * @return the set of parsed volumes
   * @throws InvalidContainerVolumeException if {@code volumes} are not valid absolute Unix paths
   */
  @VisibleForTesting
  static Set<AbsoluteUnixPath> getVolumesSet(CommonInput input)
      throws InvalidContainerVolumeException {
    Set<AbsoluteUnixPath> volumes = new HashSet<>();
    for (String path : input.rawConfiguration.getVolumes()) {
      try {
        AbsoluteUnixPath absoluteUnixPath = AbsoluteUnixPath.get(path);
        volumes.add(absoluteUnixPath);
      } catch (IllegalArgumentException exception) {
        throw new InvalidContainerVolumeException(path, path, exception);
      }
    }

    return volumes;
  }

  @VisibleForTesting
  static Optional<AbsoluteUnixPath> getWorkingDirectoryChecked(CommonInput input)
      throws InvalidWorkingDirectoryException {
    if (!input.rawConfiguration.getWorkingDirectory().isPresent()) {
      return Optional.empty();
    }

    String path = input.rawConfiguration.getWorkingDirectory().get();
    try {
      return Optional.of(AbsoluteUnixPath.get(path));
    } catch (IllegalArgumentException ex) {
      throw new InvalidWorkingDirectoryException(path, path, ex);
    }
  }

  // TODO: find a way to reduce the number of arguments.
  private static boolean configureCredentialRetrievers(
      EventDispatcher eventDispatcher,
      RegistryImage registryImage,
      ImageReference imageReference,
      String usernamePropertyName,
      String passwordPropertyName,
      AuthProperty knownAuth,
      InferredAuthProvider inferredAuthProvider,
      @Nullable String credHelper)
      throws FileNotFoundException, InferredAuthRetrievalException {
    DefaultCredentialRetrievers defaultCredentialRetrievers =
        DefaultCredentialRetrievers.init(
            CredentialRetrieverFactory.forImage(imageReference, eventDispatcher));
    Optional<Credential> optionalCredential =
        ConfigurationPropertyValidator.getImageCredential(
            eventDispatcher,
            usernamePropertyName,
            passwordPropertyName,
            knownAuth,
            knownAuth.getUsernameDescriptor(),
            knownAuth.getPasswordDescriptor());
    boolean credentialPresent = optionalCredential.isPresent();
    if (optionalCredential.isPresent()) {
      defaultCredentialRetrievers.setKnownCredential(
          optionalCredential.get(), knownAuth.getAuthDescriptor());
    } else {
      Optional<AuthProperty> optionalInferredAuth =
          inferredAuthProvider.getAuth(imageReference.getRegistry());
      credentialPresent = optionalInferredAuth.isPresent();
      if (optionalInferredAuth.isPresent()) {
        AuthProperty auth = optionalInferredAuth.get();
        String username = Verify.verifyNotNull(auth.getUsername());
        String password = Verify.verifyNotNull(auth.getPassword());
        Credential credential = Credential.basic(username, password);
        defaultCredentialRetrievers.setInferredCredential(credential, auth.getAuthDescriptor());
      }
    }
    defaultCredentialRetrievers.setCredentialHelper(credHelper);
    defaultCredentialRetrievers.asList().forEach(registryImage::addCredentialRetriever);

    return credentialPresent;
  }

  private static ImageReference getGeneratedTargetDockerTag(
      CommonInput input, HelpfulSuggestions helpfulSuggestions)
      throws InvalidImageReferenceException {
    return ConfigurationPropertyValidator.getGeneratedTargetDockerTag(
        input.rawConfiguration.getToImage().orElse(null),
        new DefaultEventDispatcher(input.projectProperties.getEventHandlers()),
        input.projectProperties.getName(),
        input.projectProperties.getVersion().equals("unspecified")
            ? "latest"
            : input.projectProperties.getVersion(),
        helpfulSuggestions);
  }

  /**
   * Configures a {@link Containerizer} with values pulled from project properties/raw build
   * configuration.
   *
   * @param containerizer the {@link Containerizer} to configure
   */
  private static void configureContainerizer(CommonInput input, Containerizer containerizer) {
    containerizer
        .setToolName(input.projectProperties.getToolName())
        .setEventHandlers(input.projectProperties.getEventHandlers())
        .setAllowInsecureRegistries(input.rawConfiguration.getAllowInsecureRegistries())
        .setBaseImageLayersCache(
            getCheckedCacheDirectory(
                PropertyNames.BASE_IMAGE_CACHE,
                Boolean.getBoolean(PropertyNames.USE_ONLY_PROJECT_CACHE)
                    ? input.projectProperties.getDefaultCacheDirectory()
                    : Containerizer.DEFAULT_BASE_CACHE_DIRECTORY))
        .setApplicationLayersCache(
            getCheckedCacheDirectory(
                PropertyNames.APPLICATION_CACHE,
                input.projectProperties.getDefaultCacheDirectory()));

    input.rawConfiguration.getToTags().forEach(containerizer::withAdditionalTag);
  }

  /**
   * Returns the value of a cache directory system property if it is set, otherwise returns {@code
   * defaultPath}.
   *
   * @param property the name of the system property to check
   * @param defaultPath the path to return if the system property isn't set
   * @return the value of a cache directory system property if it is set, otherwise returns {@code
   *     defaultPath}
   */
  private static Path getCheckedCacheDirectory(String property, Path defaultPath) {
    if (System.getProperty(property) != null) {
      return Paths.get(System.getProperty(property));
    }
    return defaultPath;
  }

  private final JibContainerBuilder jibContainerBuilder;
  private final ImageReference baseImageReference;
  private final ImageReference targetImageReference;
  private final boolean isBaseImageCredentialPresent;
  private final boolean isTargetImageCredentialPresent;
  private final Containerizer containerizer;

  private PluginConfigurationProcessor(
      JibContainerBuilder jibContainerBuilder,
      Containerizer containerizer,
      ImageReference baseImageReference,
      ImageReference targetImageReference,
      boolean isBaseImageCredentialPresent,
      boolean isTargetImageCredentialPresent) {
    this.jibContainerBuilder = jibContainerBuilder;
    this.containerizer = containerizer;
    this.baseImageReference = baseImageReference;
    this.targetImageReference = targetImageReference;
    this.isBaseImageCredentialPresent = isBaseImageCredentialPresent;
    this.isTargetImageCredentialPresent = isTargetImageCredentialPresent;
  }

  public JibContainerBuilder getJibContainerBuilder() {
    return jibContainerBuilder;
  }

  public Containerizer getContainerizer() {
    return containerizer;
  }

  public ImageReference getBaseImageReference() {
    return baseImageReference;
  }

  public ImageReference getTargetImageReference() {
    return targetImageReference;
  }

  public boolean isBaseImageCredentialPresent() {
    return isBaseImageCredentialPresent;
  }

  public boolean isTargetImageCredentialPresent() {
    return isTargetImageCredentialPresent;
  }
}
