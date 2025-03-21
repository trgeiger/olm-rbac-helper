/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/containers/image/v5/types"
	ocv1 "github.com/operator-framework/operator-controller/api/v1"
	"github.com/operator-framework/operator-registry/alpha/declcfg"
	"github.com/spf13/cobra"
	"github.com/trgeiger/olm-rbac-helper/pkg/authorization"
	catalogcache "github.com/trgeiger/olm-rbac-helper/pkg/catalogmetadata/cache"
	catalogclient "github.com/trgeiger/olm-rbac-helper/pkg/catalogmetadata/client"
	imageutil "github.com/trgeiger/olm-rbac-helper/pkg/image"
	"github.com/trgeiger/olm-rbac-helper/pkg/resolve"
	"github.com/trgeiger/olm-rbac-helper/pkg/rukpak/convert"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/release"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/tools/clientcmd"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type foundBundle struct {
	bundle   *declcfg.Bundle
	catalog  string
	priority int32
}

// checkPermissionsCmd represents the checkPermissions command
var checkPermissionsCmd = &cobra.Command{
	Use:  "kubectl olmrbac [EXTENSION_MANIFEST] [CATALOG_URL]",
	Args: cobra.ExactArgs(2),
	Long: `A tool to generate required RBAC for the installer ServiceAccount of a ClusterExtension in OLMv1`,
	Run: func(cmd *cobra.Command, args []string) {
		manifestPath := args[0]
		catalogHost := args[1]
		err := run(manifestPath, catalogHost)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func run(manifestPath string, catalogHost string) error {
	kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(kubeconfig, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %v", err)
	}
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = ocv1.AddToScheme(s)

	myClient, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	ext, err := parseClusterExtensionFromYAML(manifestPath)
	if err != nil {
		return fmt.Errorf("could not parse clusterextension manifest")
	}

	catalogCache := catalogcache.NewFilesystemCache("/tmp/catalogs")
	catalogClient := catalogclient.New(catalogCache, func() (*http.Client, error) {
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}, nil
	})

	catalogs, err := GetCatalogs(myClient)
	if err != nil {
		return fmt.Errorf("could not get catalogs: %w", err)
	}

	for _, catalog := range catalogs {
		parsedBase, err := url.Parse(catalog.Status.URLs.Base)
		if err != nil {
			return fmt.Errorf("could not parse catalog base url: %w", err)
		}
		parsedBase.Host = catalogHost
		catalog.Status.URLs.Base = parsedBase.String()
		catalogFs, err := catalogCache.Get(catalog.Name, catalog.Status.ResolvedSource.Image.Ref)
		if err != nil {
			return fmt.Errorf("problem checking catalog cache: %w", err)
		} else if catalogFs == nil {
			catalogClient.PopulateCache(context.TODO(), &catalog)
		}
	}

	resolver := &resolve.CatalogResolver{
		WalkCatalogsFunc: resolve.CatalogWalker(
			func(ctx context.Context, option ...client.ListOption) ([]ocv1.ClusterCatalog, error) {
				var catalogs ocv1.ClusterCatalogList
				if err := myClient.List(ctx, &catalogs, option...); err != nil {
					return nil, err
				}
				return catalogs.Items, nil
			},
			catalogClient.GetPackage,
		),
		Validations: []resolve.ValidationFunc{
			resolve.NoDependencyValidation,
		},
	}

	var bm *ocv1.BundleMetadata

	bundle, _, _, err := resolver.Resolve(context.TODO(), ext, bm)
	if err != nil {
		return fmt.Errorf("could not resolve bundle: %w", err)
	}

	imagePuller := &imageutil.ContainersImagePuller{
		SourceCtxFunc: func(ctx context.Context) (*types.SystemContext, error) {
			srcContext := &types.SystemContext{
				// DockerCertPath: cfg.pullCasDir,
				// OCICertPath:    cfg.pullCasDir,
			}
			// if _, err := os.Stat(authFilePath); err == nil && globalPullSecretKey != nil {
			// 	logger.Info("using available authentication information for pulling image")
			// 	srcContext.AuthFilePath = authFilePath
			// } else if os.IsNotExist(err) {
			// 	logger.Info("no authentication information found for pulling image, proceeding without auth")
			// } else {
			// 	return nil, fmt.Errorf("could not stat auth file, error: %w", err)
			// }
			return srcContext, nil
		},
	}

	imageCache := imageutil.BundleCache("/tmp/bundles")

	image, _, _, err := imagePuller.Pull(context.TODO(), ext.GetName(), bundle.Image, imageCache)
	if err != nil {
		return fmt.Errorf("could not pull bundle image: %w", err)
	}

	chart, err := convert.RegistryV1ToHelmChart(image, ext.Spec.Namespace, "")
	if err != nil {
		return fmt.Errorf("could not convert image to helm chart: %w", err)
	}
	release, err := renderHelmManifests(ext, chart)
	if err != nil {
		return fmt.Errorf("could not convert chart to manifests: %w", err)
	}

	userInfo := user.DefaultInfo{Name: fmt.Sprintf("system:serviceaccount:%s:%s", ext.Spec.Namespace, ext.Spec.ServiceAccount.Name)}
	preAuth := authorization.NewRBACPreAuthorizer(myClient)
	missingRules, err := preAuth.PreAuthorize(context.TODO(), &userInfo, strings.NewReader(release.Manifest))
	if err != nil {
		fmt.Println(fmt.Errorf("could not check for missing rules: %w", err))
	}

	missingRulesObjects := []runtime.Object{}
	for _, namespacedRules := range missingRules {
		if namespacedRules.Namespace == "" {
			missingRulesObjects = append(missingRulesObjects, &rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRole",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "missing-required-cluster-permissions",
				},
				Rules: namespacedRules.MissingRules,
			})
		} else {
			missingRulesObjects = append(missingRulesObjects, &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "Role",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "missing-required-namespaced-permissions",
					Namespace: namespacedRules.Namespace,
				},
				Rules: namespacedRules.MissingRules,
			})
		}
	}

	serializer := json.NewYAMLSerializer(json.DefaultMetaFactory, nil, nil)

	output := os.Stdout
	if fileOutput != "" {
		file, err := os.Create(fileOutput)
		output = file
		if err != nil {
			return fmt.Errorf("could not create output file: %w", err)
		}
		defer file.Close()
	}
	for _, obj := range missingRulesObjects {
		err := serializer.Encode(obj, output)
		if err != nil {
			return fmt.Errorf("could not encode yaml objects to output: %w", err)
		}
		fmt.Println("---")
	}

	return nil
}

func renderHelmManifests(ext *ocv1.ClusterExtension, chart *chart.Chart) (*release.Release, error) {
	actionConfig := new(action.Configuration)
	settings := cli.New()

	// Initialize Helm action client
	if err := actionConfig.Init(settings.RESTClientGetter(), ext.Spec.Namespace, "memory", log.Printf); err != nil {
		return nil, fmt.Errorf("failed to initialize Helm action client: %w", err)
	}

	// Create Helm install action for rendering
	install := action.NewInstall(actionConfig)
	install.ReleaseName = ext.GetName()
	install.DryRun = true // Dry-run to render without applying
	install.IsUpgrade = false
	install.IncludeCRDs = true
	install.ClientOnly = true
	install.Replace = true

	// Execute dry-run install
	release, err := install.Run(chart, nil)
	if err != nil {
		return nil, fmt.Errorf("render error: %w", err)
	}

	return release, nil
}

func parseClusterExtensionFromYAML(filePath string) (*ocv1.ClusterExtension, error) {
	var ext ocv1.ClusterExtension
	scheme := runtime.NewScheme()
	_ = ocv1.AddToScheme(scheme)
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDeserializer()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	obj, _, err := decoder.Decode(data, nil, &ext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode clusterextension manifest")
	}

	return obj.(*ocv1.ClusterExtension), nil
}

func GetCatalogs(cl client.Client) ([]ocv1.ClusterCatalog, error) {
	var catalogs ocv1.ClusterCatalogList
	if err := cl.List(context.Background(), &catalogs); err != nil {
		return nil, err
	}
	return catalogs.Items, nil
}
