package cmd

import (
	"fmt"
	"os"

	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// Conf is the config struct
var Conf *Config

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "keepsake",
	Short: "Update certificates from vault",
	Long:  `Check validity of certificates and update them as needed`,

	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/keepsake.yaml)")
	// allow overriding log level on command line
	rootCmd.PersistentFlags().String("log-level", "info", "log level to use (trace|debug|info|warning|error|fatal|panic)")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Read the default config from etc
		viper.AddConfigPath("/etc")
		viper.SetConfigName("keepsake")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
	// Custom decode hook initialization
	opt := viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		// Custom Decode Hook Function to parse validity tests
		DecodeValidityFuncsHookFunc(),
	))
	if err := viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level")); err != nil {
		fmt.Printf("parsing log-level flag wrong: %s", err)
		os.Exit(1)
	}
	if err := viper.Unmarshal(&Conf, opt); err != nil {
		fmt.Printf("Error reading '%s', config problem: %v", viper.ConfigFileUsed(), err)
	}
	initLogging()
}

func initLogging() {
	switch Conf.LogType {
	case "json":
		formatter := &log.JSONFormatter{
			FieldMap: log.FieldMap{
				log.FieldKeyTime:  "@timestamp",
				log.FieldKeyLevel: "@level",
				log.FieldKeyMsg:   "@message",
			}}
		log.SetFormatter(formatter)
	}
	level, err := log.ParseLevel(Conf.LogLevel)
	if err != nil {
		log.Warnf("Unable to parse loglevel, error: %s", err)
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(level)
	}
}
