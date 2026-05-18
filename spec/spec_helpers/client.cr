module PlaceOS::Auth::SpecClient
  # ivars aren't allowed at the top level, so wrap the spec client in a constant.
  private CLIENT = ActionController::SpecHelper.client

  def client
    CLIENT
  end
end
