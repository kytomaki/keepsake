package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	done                            chan bool
	controlChannels, returnChannels []chan bool
)

// daemonCmd updates Certs from vault to the end of time
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run forever",
	Long:  `Work as daemon updating the certificates as needed`,
	Run: func(cmd *cobra.Command, args []string) {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
		go handleSignals(signals)
		startWatchingCertificates()
		<-done
		stopWatchingCertificates()
		log.Info("exiting")
	},
}

func init() {
	updateCmd.AddCommand(daemonCmd)
	done = make(chan bool, 1)
}

func handleSignals(signalChannel chan os.Signal) {
	for {
		signal := <-signalChannel
		log.Infof("caught signal: %s", signal)
		switch signal {
		case syscall.SIGHUP:
			reloadConfig()
			startWatchingCertificates()
		case syscall.SIGINT, syscall.SIGTERM:
			done <- true
			return
		default:
		}
	}
}

func reloadConfig() {
	stopWatchingCertificates()
	// Reload configuration
	initConfig()
}

func stopWatchingCertificates() {
	// Stop existing functions
	for _, controlChannel := range controlChannels {
		controlChannel <- true
	}
	// make sure we're done
	for _, returnChannel := range returnChannels {
		<-returnChannel
	}
	// Clean up configurations
	controlChannels = nil
	returnChannels = nil
	Conf = nil
}

func startWatchingCertificates() {
	readInCertificates()
	for _, cconf := range Conf.Certificates {
		controlChannel := make(chan bool, 1)
		returnChannel := make(chan bool, 1)
		log.Infof("starting watching for: %s", cconf.CName)
		go cconf.updateInvalidCertificateAdInfinitum(controlChannel, returnChannel)
		controlChannels = append(controlChannels, controlChannel)
		returnChannels = append(returnChannels, returnChannel)
	}
}

func (cconf *CertificateConf) updateInvalidCertificateAdInfinitum(controlChannel, returnChannel chan bool) {
	for {
		cconf.updateInvalidCertificate()
		certTimerDuration := MultipliedDuration(time.Until(cconf.ClientCertificate.NotAfter), Conf.RenewalCoefficient)
		rootTimerDuration := MultipliedDuration(time.Until(cconf.RootCertificate[0].NotAfter), Conf.RenewalCoefficient)
		for _, cert := range cconf.RootCertificate {
			dur := MultipliedDuration(time.Until(cert.NotAfter), Conf.RenewalCoefficient)
			if dur < rootTimerDuration {
				rootTimerDuration = dur
			}
		}
		certTimer := time.NewTimer(certTimerDuration)
		defer certTimer.Stop()
		rootTimer := time.NewTimer(rootTimerDuration)
		defer rootTimer.Stop()
		select {
		case <-controlChannel:
			log.Infof("stopping watching for: %s", cconf.CName)
			returnChannel <- true
			return
		case <-certTimer.C:
			log.Infof("certificate: %s renewal time", cconf.CName)
		case <-rootTimer.C:
			log.Infof("root or intermediate cert renewal for certificate: %s", cconf.CName)
		}

	}

}
