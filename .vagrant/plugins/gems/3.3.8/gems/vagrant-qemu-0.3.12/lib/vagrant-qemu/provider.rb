require "log4r"
require "vagrant"

require_relative "driver"

module VagrantPlugins
  module QEMU
    class Provider < Vagrant.plugin("2", :provider)
      attr_reader :driver

      def initialize(machine)
        @machine = machine

        # TODO support NFS
        @machine.config.nfs.functional = false

        # This method will load in our driver, so we call it now to
        # initialize it.
        machine_id_changed
      end

      def action(name)
        # Attempt to get the action method from the Action class if it
        # exists, otherwise return nil to show that we don't support the
        # given action.
        action_method = "action_#{name}"
        return Action.send(action_method) if Action.respond_to?(action_method)
        nil
      end

      def machine_id_changed
        @driver = Driver.new(@machine.id, @machine.data_dir, @machine.env.tmp_path)
      end

      def ssh_info
        # If the VM is not running that we can't possibly SSH into it
        return nil if state.id != :running

        return {
          host: @machine.provider_config.ssh_host,
          port: @machine.provider_config.ssh_port
        }
      end

      def state
        state_id = nil
        state_id = :not_created if !@machine.id

        if !state_id
          # Run a custom action we define called "read_state" which does
          # what it says. It puts the state in the `:machine_state_id`
          # key in the environment.
          env = @machine.action(:read_state)
          state_id = env[:machine_state_id]
        end

        # Get the short and long description
        short = state_id.to_s
        long  = ""

        # If we're not created, then specify the special ID flag
        if state_id == :not_created
          state_id = Vagrant::MachineState::NOT_CREATED_ID
        end

        # Return the MachineState object
        Vagrant::MachineState.new(state_id, short, long)
      end

      def to_s
        id = @machine.id.nil? ? "new" : @machine.id
        "QEMU (#{id})"
      end
    end
  end
end
